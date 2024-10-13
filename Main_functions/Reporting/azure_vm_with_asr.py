import logging
import os
import sys
from datetime import datetime, timedelta
sys.path.append('.')
sys.path.append(r'c:\program files\microsoft sdks\azure\cli2\lib\site-packages')
from azure.mgmt.recoveryservicessiterecovery.models import A2AReplicationDetails
from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient
from azure.mgmt.recoveryservices import RecoveryServicesClient
from azure.mgmt.recoveryservicessiterecovery import SiteRecoveryManagementClient
from azure.core.exceptions import HttpResponseError
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

# Check ASR replication status 
def check_asr_replication(vm_name, subscription_id, credential):
    recovery_client = RecoveryServicesClient(credential=credential, subscription_id=subscription_id)
    vaults = recovery_client.vaults.list_by_subscription_id()
    # Get Vaults of given subscription
    for vault in vaults:
        vault_name = vault.name
        vault_rg = vault.id.split('/')[4]
        # Get replicated items using this Object
        site_recovery_client = SiteRecoveryManagementClient(
            credential=credential,
            subscription_id=subscription_id,
            resource_group_name=vault_rg,
            resource_name=vault_name
        )
        
        replicated_items = site_recovery_client.replication_protected_items.list()
        # Loop every item get the details
        for item in replicated_items:
            item_properties = item.properties
            friendly_name = getattr(item_properties, 'friendly_name', None)
            # check if input given vm name and replicate item vm name. if both are equal then its ASR configured
            if friendly_name and vm_name.lower() in friendly_name.lower():
                provider_specific_details = item_properties.provider_specific_details
                replication_health = item_properties.replication_health
                agent_version = getattr(provider_specific_details, 'agent_version', 'N/A')
                #agent_status = getattr(provider_specific_details, 'agent_status', 'N/A')
                
                return {
                    'vault_rg': vault_rg,
                    'vault_name': vault_name,
                    'replication_health': replication_health,
                    #'agent_status': agent_status,
                    'agent_version': agent_version
                }
    
    return None

def process_subscription(subscription, credential):
    try:
        subscription_name = subscription.display_name
        subscription_id = subscription.subscription_id
        compute_client = ComputeManagementClient(credential, subscription_id)
        resource_client = ResourceManagementClient(credential, subscription_id)
        subscription_tags = resource_client.tags.get_at_scope(f"/subscriptions/{subscription_id}")
        sub_tags = subscription_tags.properties.tags
        vms_detailed_info = []
        vms = list(compute_client.virtual_machines.list_all())
 
        with ThreadPoolExecutor() as vm_executor:
            vm_results = vm_executor.map(lambda vm: process_vm(vm, compute_client, subscription_name, subscription_id, sub_tags, credential), vms)
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

def process_vm(vm, compute_client, subscription_name, subscription_id, sub_tags, credential):
    try:
        vm_name = vm.name
        vm_resource_group = vm.id.split('/')[4]
        if 'databricks' not in vm_resource_group.lower() and 'citrix' not in vm_resource_group.lower():
        
            # Check if ASR is configured for the VM
            asr_details = check_asr_replication(vm_name=vm_name, subscription_id=subscription_id, credential=credential)
            if asr_details:
                location = vm.location
                cst_time = datetime.utcnow() - timedelta(hours=6)
                cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')

                return {
                    'SubscriptionName': subscription_name,
                    'SubscriptionID': subscription_id,
                    'VMName': vm_name,
                    'VM_RG': vm_resource_group,
                    'Location': location,
                    'Vault_RG': asr_details['vault_rg'],
                    'Vault_Name': asr_details['vault_name'],
                    'Replication_Health': asr_details['replication_health'],
                    #'Agent_Status': asr_details['agent_status'],
                    'Agent_Version': asr_details['agent_version'],
                    'Sub_Tag': str(sub_tags) if sub_tags else "N/A",
                    'Timestamp': str(cst_time_str)
                }
            else:
                return None  # Skip if ASR is not configured
    
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
        if vms_detailed_info:  # Only process if there's data
            df = pd.DataFrame(vms_detailed_info)
            table_name = 'azure_vm_with_asr'
            
            columns = ['SubscriptionName', 'SubscriptionID', 'VMName', 'VM_RG', 'Location', 'Vault_RG', 'Vault_Name', 'Replication_Health', 'Agent_Version', 'Sub_Tag', 'Timestamp']
            container_name = 'azure-vm-with-asr' 
            notifications_email.send_email(container_name, container_name + ' Data Report', "excel", container_name, df)
            Azure_SQL_Convertion.SQL_function(df, table_name, columns)
            Azure_Blob_Convertion.Blob_function(df, container_name, 'main_name')

    except Exception as e:
        logger.error(f"Error occurred during main execution: {e}")
    finally:
        # Retrieve logs from the handler
        all_logs = csv_error_handler.get_all_logs()
        error_logs = csv_error_handler.get_error_logs()
        # Save all logs and error logs to Blob Storage
        if all_logs:
            all_logs_df = pd.DataFrame(all_logs)
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-vm-with-asr', 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-vm-with-asr', 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('azure-vm-with-asr', 'azure-vm-with-asr' +' Error Report', "excel", 'azure-vm-with-asr', error_logs_df)


if __name__ == "__main__":
    main()
