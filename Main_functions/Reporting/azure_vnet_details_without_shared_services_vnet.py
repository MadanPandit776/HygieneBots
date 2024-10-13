import logging
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.subscription import SubscriptionClient
import pandas as pd
import sys
import os
sys.path.append('.')
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from Class.Report_handler import Azure_SQL_Convertion
from Class.Report_handler import Azure_Blob_Convertion
from Class.Logging.csv_error_handler import CSVErrorHandler
from Class.Email import notifications_email
from Class.Logging import subscriptions_validations


data = []
# Define the shared VNets
sharedservice_vnets = [
    "pep-sharedservice-01-scus-vnet",
    "pep-sharedservice-01-eus-vnet",
    "pep-sharedservice-01-suk-vnet",
    "pep-sharedservice-01-gws-vnet",
    "pep-sharedservice-01-sea-vnet",
    "pep-sharedservice-01-ae-vnet"
]

csv_error_handler = CSVErrorHandler()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(csv_error_handler)

def main():
    try:
        # Initialize Azure credential
        credential = DefaultAzureCredential()
        subscription_client = SubscriptionClient(credential)       
        user_input = sys.argv[1] if len(sys.argv) > 1 else "all"

        # Get subscriptions based on user input
        if user_input.lower() == "all":
            subscriptions = subscription_client.subscriptions.list()
        else:
            subscription_names = [s.strip() for s in user_input.split(",")]
            subscriptions = [s for s in subscription_client.subscriptions.list() if s.display_name in subscription_names]
            valid_subs, invalid_subs = subscriptions_validations.check_valid_subscription_names(subscription_names)
            if invalid_subs:
                logger.error(f"invalid input subscriptions {invalid_subs}")

        # Iterate through each subscription
        for subscription in subscriptions:
            # Initialize the Network Management Client
            network_client = NetworkManagementClient(credential, subscription.subscription_id)
            # List all virtual networks in the subscription
            vnets = network_client.virtual_networks.list_all()
            # Check each VNet for peering with shared VNets
            for vnet in vnets:
                try:
                    vnet_address_space = ", ".join(vnet.address_space.address_prefixes) if vnet.address_space and vnet.address_space.address_prefixes else None
                    for peering in vnet.virtual_network_peerings:
                        if peering.remote_virtual_network.id.endswith(tuple(sharedservice_vnets)):
                            # Fetch resource group from vnet.id
                            resource_group = vnet.id.split("/resourceGroups/")[1].split("/")[0]

                            # Fetch subnet details
                            subnets = network_client.subnets.list(resource_group_name=resource_group, virtual_network_name=vnet.name)
                            for subnet in subnets:
                                cst_time = datetime.utcnow() - timedelta(hours=6)
                                cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
                                # Calculate unused IPs
                                connected_devices = len(subnet.ip_configurations) if subnet.ip_configurations else 0
                                if subnet.address_prefix:
                                    prefix_length = int(subnet.address_prefix.split("/")[1])
                                    total_ips = 2 ** (32 - prefix_length)
                                    usable_ips = total_ips - 5
                                else:
                                    usable_ips = 0
                                unused_ips = usable_ips - connected_devices if connected_devices is not None else None
                                service_endpoints = [se.service for se in subnet.service_endpoints] if subnet.service_endpoints else []
                                nsg = subnet.network_security_group
                                nsg_name = nsg.id.split('/')[-1] if nsg and nsg.id else None
                                nsg_rg = subnet.network_security_group.id.split("/resourceGroups/")[1].split("/")[0] if nsg and nsg.id else None

                                data.append({
                                    "SubscriptionName": str(subscription.display_name),
                                    "Resource_Group": resource_group,
                                    "VNet_Name": vnet.name,
                                    "Shared_VNet": peering.remote_virtual_network.id.split("/virtualNetworks/")[1],
                                    "VNet_Address_Space": vnet_address_space,
                                    "Subnet_Name": subnet.name,
                                    "Sub_Prefix": str(subnet.address_prefix),
                                    "NSG": nsg_name if nsg_name else "",
                                    "NSG_rg": nsg_rg if nsg_rg else "",
                                    "Total_IPs": str(total_ips),
                                    "Usable_IPs": str(usable_ips),
                                    "Service_Endpoints": ", ".join(service_endpoints),
                                    "VNet_DNS_Server": str(vnet.dhcp_options.dns_servers if vnet.dhcp_options else None),
                                    "Unused_IPs": str(unused_ips),
                                    'Timestamp': str(cst_time_str)
                                })
                                logger.info(f"Virtual network '{vnet.name}' processed successfully in subscription {subscription.display_name}")
                except Exception as e:
                    logger.error(f"Error processing subscription {subscription.display_name}: {e}")

        # Create a DataFrame from the collected data
        df = pd.DataFrame(data)
        
        # Save results to Azure SQL and Blob Storage
        table_name = 'azure_vnet_details_without_shared_services_vnet'
        container_name = 'azure-vnet-details-without-shared-services-vnet'   
    
        columns = ['SubscriptionName', 'Resource_Group', 'VNet_Name', 'Shared_VNet', 'VNet_Address_Space', 'Subnet_Name', 'Sub_Prefix', 'NSG', 'NSG_RG', 'Total_IPs', 'Usable_IPs', 'Service_Endpoints', 'VNet_DNS_Server', 'Unused_IPs', 'Time_Zone']
        
        if not df.empty:
            Azure_SQL_Convertion.SQL_function(df, table_name, columns)
            Azure_Blob_Convertion.Blob_function(df, container_name, 'main_name')
            notifications_email.send_email(container_name, container_name + ' Data Report', "excel", container_name, df)
            
    except Exception as e:
        logger.error(f"An error occurred: {e}")
    finally:
        # Retrieve logs from the handler
        all_logs = csv_error_handler.get_all_logs()
        error_logs = csv_error_handler.get_error_logs()
        
        # Save all logs and error logs to Blob Storage
        if all_logs:
            all_logs_df = pd.DataFrame(all_logs)
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-vnet-details-without-shared-services-vnet', 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-vnet-details-without-shared-services-vnet', 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('Exception log file generated', 'azure-vnet-details-without-shared-services-vnet' + ' Exception Report', "excel", 'azure-vnet-details-without-shared-services-vnet', error_logs_df)   

if __name__ == "__main__":
    main()
