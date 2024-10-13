import logging
import os
import sys
sys.path.append('.')
sys.path.append(r'c:\program files\microsoft sdks\azure\cli2\lib\site-packages')
import requests
from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient
from azure.mgmt.recoveryservices import RecoveryServicesClient
from azure.mgmt.recoveryservicessiterecovery import SiteRecoveryManagementClient
from datetime import datetime, timedelta
from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
import pandas as pd
from concurrent.futures import ThreadPoolExecutor
from Class.Email import notifications_email
from Class.Report_handler import Azure_SQL_Convertion
from Class.Report_handler import Azure_Blob_Convertion
from Class.Logging.csv_error_handler import CSVErrorHandler
from Class.Logging import subscriptions_validations

# Create lists to store logs
all_logs = []
error_logs = []

# Instantiate the handler
csv_error_handler = CSVErrorHandler()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(csv_error_handler)

# Check ASR configution 
def check_asr_replication(vm_name, subscription_id, credential):
    recovery_client = RecoveryServicesClient(credential=credential, subscription_id=subscription_id)
    vaults = recovery_client.vaults.list_by_subscription_id()
    # Get Vaults of inside the subscriptions
    for vault in vaults:
        vault_name = vault.name
        vault_rg = vault.id.split('/')[4]
        # Object get the Vault replicated items
        site_recovery_client = SiteRecoveryManagementClient(
            credential=credential,
            subscription_id=subscription_id,
            resource_group_name=vault_rg,
            resource_name=vault_name
        )
        
        replicated_items = site_recovery_client.replication_protected_items.list()
        # Loop every replicated item
        for item in replicated_items:
            item_properties = item.properties
            friendly_name = getattr(item_properties, 'friendly_name', None)
            # check in item contains the name of VM is euql to input given vm name. If both are equal then its ASR configured 
            if friendly_name and vm_name.lower() in friendly_name.lower():
                print(f"VM '{vm_name}' is replicated by ASR in vault '{vault.name}'.")
                return True
    
    return False
# Get the SKU size of VM
def get_vm_specs_from_sku(sku, vm_size_list):
    for vm_size in vm_size_list:
        if vm_size.name == sku:
            memory_gb = vm_size.memory_in_mb / 1024  # Convert MB to GB
            cpu = vm_size.number_of_cores
            return memory_gb, cpu
    return 'Unknown', 'Unknown'

def process_subscription(subscription, credential):
    try:
        subscription_name = subscription.display_name
        subscription_id = subscription.subscription_id
        compute_client = ComputeManagementClient(credential, subscription_id)
        resource_client = ResourceManagementClient(credential, subscription_id)
        network_client = NetworkManagementClient(credential, subscription_id)
        subscription_tags = resource_client.tags.get_at_scope(f"/subscriptions/{subscription_id}")
        sub_tags = subscription_tags.properties.tags
        vms_detailed_info = []
        vms = list(compute_client.virtual_machines.list_all())
 
        with ThreadPoolExecutor() as vm_executor:
            vm_results = vm_executor.map(lambda vm: process_vm(vm, compute_client, network_client, subscription_name, subscription_id, sub_tags, credential), vms)
            for result in vm_results:
                if result:
                    vms_detailed_info.append(result)
        return vms_detailed_info
    except HttpResponseError as e:
        logger.error(f"HTTP error occurred during subscription {subscription.display_name} processing: {e}")
        return []
    except Exception as e:
        logger.error(f"An error occurred during subscription {subscription.display_name} processing: {e}")
        return []

# get VM details 
def process_vm(vm, compute_client, network_client, subscription_name, subscription_id, sub_tags, credential):
    try:
        vm_name = vm.name
        vm_resource_group = vm.id.split('/')[4]
        # Ignore if rg contains name like "databricks and citrix"
        if 'databricks' not in vm_resource_group.lower() and 'citrix' not in vm_resource_group.lower():
            location = vm.location
            vm_sizes = list(compute_client.virtual_machine_sizes.list(location=location))
            vm_sku = vm.hardware_profile.vm_size
            memory_gb, cpu = get_vm_specs_from_sku(vm_sku, vm_sizes)
            data_disk_size = 0
            os_disk_size = 0
            for disk in vm.storage_profile.data_disks:
                disk_size_gb = disk.disk_size_gb
                if disk_size_gb is not None:
                    data_disk_size += disk_size_gb
            # Get OS disk size
            if vm.storage_profile.os_disk.disk_size_gb is not None:
                os_disk_size = vm.storage_profile.os_disk.disk_size_gb

            # Print or process the VM and disk sizes
            total_disk_size = data_disk_size + os_disk_size

            instance_view = compute_client.virtual_machines.instance_view(vm_resource_group, vm_name)
            power_state = 'Unknown'
            # check VM status 
            if instance_view and hasattr(instance_view, 'statuses') and instance_view.statuses:
                statuses = instance_view.statuses
                power_state = next((s.display_status for s in statuses if s.code.startswith('PowerState/')), 'Unknown')
            # Get VM Network interface details
            network_interfaces = vm.network_profile.network_interfaces
            for nic in network_interfaces:
                try:
                    nic_name = nic.id.split('/')[-1]
                    nic_rg = nic.id.split('/')[4]
                    nic_details = network_client.network_interfaces.get(nic_rg, nic_name)
                    nsg_name = "N/A"
                    for ip_config in nic_details.ip_configurations:
                        private_ip = ip_config.private_ip_address
                        public_ip = "N/A"
                        vnet_prefix = "N/A"
                        subnet_prefix = 'N/A'
                        route_table_name = 'N/A'
                        route_table_rg = 'N/A'
                        bgpstatus = 'Not Configured'
                        subnet_prefixes = []
                        # Get Public IP
                        if ip_config.public_ip_address:
                            public_ip_id = ip_config.public_ip_address.id.split('/')[-1]
                            public_ip_details = network_client.public_ip_addresses.get(nic_rg, public_ip_id)
                            public_ip = public_ip_details.ip_address

                        subnet_id = ip_config.subnet.id if ip_config.subnet else None
                        subnet_name = subnet_id.split('/')[-1] if subnet_id else None
                        # Get Subnet Details of VM
                        if subnet_id:
                            vnet_rg = ip_config.subnet.id.split('/')[4]
                            vnet_name = subnet_id.split('/')[8] if len(subnet_id.split('/')) > 8 else None
                            vnet_details = network_client.virtual_networks.get(vnet_rg, vnet_name)
                            vnet_prefix = vnet_details.address_space.address_prefixes
                            subnet_details = network_client.subnets.get(vnet_rg, vnet_name, subnet_name)
                            if subnet_details.address_prefix:
                                subnet_prefixes.append(subnet_details.address_prefix)
                            if subnet_details.address_prefixes:
                                subnet_prefixes.extend(subnet_details.address_prefixes)
                            route_table_id = subnet_details.route_table.id if subnet_details.route_table else None
                            nsg_id = subnet_details.network_security_group.id if subnet_details.network_security_group else None
                            # Get NSG details
                            if nsg_id:
                                nsg_name = nsg_id.split('/')[-1]
                                nsg_rg = nsg_id.split('/')[4]
                            # Get Route table details
                            if route_table_id:
                                route_table_name = route_table_id.split('/')[-1]
                                route_table_rg = route_table_id.split('/')[4]
                                route_table = network_client.route_tables.get(route_table_rg, route_table_name)
                                #route_table_bgp_status = getattr(route_table, 'bgp_status', 'Not Configured')
                                route_table_bgp_status = getattr(route_table, 'disable_bgp_route_propagation', "Not Configured")
                                bgpstatus = "N/A"
                                if route_table_bgp_status:
                                    bgpstatus="Not Configured"
                                else :
                                    bgpstatus="Configured"


                except ResourceNotFoundError as ex:
                    logger.error(f"Network interface not found for VM ({vm_name}): {ex}")

            cst_time = datetime.utcnow() - timedelta(hours=6)
            cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
            # Check ASR configuration
            if check_asr_replication(vm_name=vm_name, subscription_id=subscription_id, credential=credential):
                AzureSiteRecovery_Configured = 'Enabled'
            else:
                AzureSiteRecovery_Configured = 'Disabled'
            # Example usage
            data_disks_length = len(vm.storage_profile.data_disks)
            data_disks_length_str = str(data_disks_length)

            return {
                'SubscriptionName': subscription_name,
                'SubscriptionID': subscription_id,
                'VMName': vm_name,
                'VM_RG': vm_resource_group,
                'Location': location,
                'PowerStatus': power_state,
                'SKU': str(vm_sku) if vm_sku else 'N/A',
                'CPU': str(cpu) if cpu else 'N/A',
                'Memory': str(memory_gb) if memory_gb else 'N/A',
                'NumberOfDisks': data_disks_length_str if data_disks_length_str else 'N/A',
                'Type': str(vm.storage_profile.os_disk.os_type) if vm.storage_profile.os_disk.os_type else 'N/A',
                'Size': str(total_disk_size) if total_disk_size else 'N/A',
                'Private_Ip_address': str(private_ip) if private_ip else 'N/A' ,
                'Public_Ip_address': str(public_ip) if public_ip else 'N/A' ,
                'vnet': str(vnet_name) if vnet_name else 'N/A',
                'vnet_prefix': str(vnet_prefix) if vnet_prefix else 'N/A',
                'subnet_name': str(subnet_name) if subnet_name else 'N/A',
                'Subnet_prefix': ', '.join(subnet_prefixes) if subnet_prefixes else 'N/A',
                'RouteTableName': str(route_table_name) if route_table_name else 'N/A',
                'RouteTable_RG': str(route_table_rg) if route_table_rg else 'N/A',
                'RouteTable_BGP_Status': str(bgpstatus) if bgpstatus else 'N/A',
                'NetworkSecurityGroup': nsg_name if nsg_name else 'N/A',
                'NSG RG': nsg_rg if nsg_rg else 'N/A',
                'AzureSiteRecovery_Configured': AzureSiteRecovery_Configured if AzureSiteRecovery_Configured else 'N/A',
                'Sub_Tag': str(sub_tags) if sub_tags else "N/A",
                'Timestamp': str(cst_time_str)
            }
    except Exception as e:
        logger.error(f"Error occurred during VM {vm_name} processing: {e}")
        return None

def list_vms_detailed_info():
    try:
        credential = DefaultAzureCredential()
        subscription_client = SubscriptionClient(credential)
        user_input = sys.argv[1] if len(sys.argv) > 1 else "all"
        if user_input.lower() == "all":
            subscriptions = subscription_client.subscriptions.list()
        else:
            subscription_names = [s.strip() for s in user_input.split(",")]
            subscriptions = [s for s in subscription_client.subscriptions.list() if s.display_name in subscription_names]
            valid_subs, invalid_subs = subscriptions_validations.check_valid_subscription_names(subscription_names)
            if invalid_subs:
                logger.error(f"Invalid subscription names: {', '.join(invalid_subs)}")
        all_vms_detailed_info = []
        with ThreadPoolExecutor() as subscription_executor:
            sub_results = subscription_executor.map(lambda sub: process_subscription(sub, credential), subscriptions)
            for result in sub_results:
                if result:
                    all_vms_detailed_info.extend(result)
        return all_vms_detailed_info
    except Exception as e:
        logger.error(f"Error occurred during subscription processing: {e}")
        return []

def main():
    try:
        vms_detailed_info = list_vms_detailed_info()
        df = pd.DataFrame(vms_detailed_info)
        table_name = 'azure_vm_property_details'
        columns = ['SubscriptionName','SubscriptionID', 'VMName', 'VM_RG', 'Location', 'PowerStatus', 'SKU', 'CPU', 'Memory', 'NumberOfDisks', 'Type', 'Size', 'Private_Ip_address', 'Public_Ip_address', 'vnet', 'vnet_prefix', 'subnet_name','Subnet_prefix', 'RouteTableName', 'RouteTable_RG', 'RouteTable_BGP_Status', 'NetworkSecurityGroup','NSG_RG','ASR_Configured', 'Sub_Tag', 'Timestamp' ]
        container_name = 'azure-vm-property-details'
        if vms_detailed_info:
            notifications_email.send_email(container_name, container_name +' Data Report', "excel", container_name, df)
            Azure_SQL_Convertion.SQL_function(df, table_name, columns)
            Azure_Blob_Convertion.Blob_function(df, container_name, 'main_name')

    except Exception as e:
        logger.error(f"An error occurred in the main execution: {e}")
    finally:
        # Retrieve logs from the handler
        all_logs = csv_error_handler.get_all_logs()
        error_logs = csv_error_handler.get_error_logs()
        # Save all logs and error logs to Blob Storage
        if all_logs:
            all_logs_df = pd.DataFrame(all_logs)
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-vm-property-details', 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-vm-property-details', 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('azure-vm-property-details', 'azure-vm-property-details' +' Error Report', "excel", 'azure-vm-property-details', error_logs_df)


if __name__ == "__main__":
    main()
