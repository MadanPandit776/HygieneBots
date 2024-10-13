import logging
import datetime
import time
import requests
from azure.identity import DefaultAzureCredential
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.storage.blob import BlobServiceClient
from azure.mgmt.resource import ResourceManagementClient
from azure.core.exceptions import HttpResponseError
import sys
sys.path.append('.')
import pandas as pd
import time
from azure.core.exceptions import HttpResponseError
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
 
# Initialize credentials and client
credential = DefaultAzureCredential()

# In activity logs we have to exclude these caller id's, even if subscription having these callers did changes igonre (consider as unused subscription)
EXCLUDED_CALLER_IDS = [
    "3849d98c-c28c-4305-8fde-98f93f175577",
    "37a2667c-78e4-4c4e-b12a-7ae558871d9b",
    "f91628e3-0d37-4a4e-b9f4-47ac1cb419c0",
    "Microsoft.Advisor",
    "bbfb2dca-4b29-48cd-b899-a5710e70a2ef",
    "AcmClient@microsoft.com"
]
 
import datetime
# Function to check activity logs with retries
chunk_size = datetime.timedelta(days=1)  # Query logs in 1-day chunks
retries = 3
delay = 5
import datetime
end_time = datetime.datetime.utcnow()
start_time = end_time - datetime.timedelta(days=89)

#function for check activity logs of subscription
def check_activity_logs(subscription_id, sub_name):
    logsenabled = False
    client = MonitorManagementClient(credential, subscription_id)
   
    current_start = start_time
    while current_start < end_time:
        current_end = min(current_start + chunk_size, end_time)
        filter_str = f"eventTimestamp ge '{current_start.isoformat()}' and eventTimestamp le '{current_end.isoformat()}'"
       
        for attempt in range(retries):
            try:
                logger.info(f"Using filter: {filter_str}")  # Debug statement for filter string
                # Query for activity logs
                activity_logs = client.activity_logs.list(filter=filter_str)
                log_count = 0
                valid_log_found = False
                # List of activity logs
                for log in activity_logs:
                    log_count += 1
                    if log.caller and log.caller not in EXCLUDED_CALLER_IDS:
                        logger.info(f"Valid log found from caller: {log.caller}")
                        logsenabled = True
                        valid_log_found = True
                        break  # Break inner loop when a valid log is found
 
                logger.info(f"Total logs found: {log_count} from {current_start} to {current_end}")
 
                if valid_log_found:
                    break  # Break retry loop on success
 
            except HttpResponseError as e:
                logger.error(f"HttpResponseError checking activity logs for subscription {subscription_id}: {e}")
                logsenabled = True  # Consider as used if there is any error
                break  # Break retry loop on error
            except Exception as e:
                logger.error(f"Error checking activity logs for subscription {subscription_id}: {e}")
                logsenabled = True  # Consider as used if there is any error
                break  # Break retry loop on error
 
            if attempt < retries - 1:
                logger.info(f"Retrying... attempt {attempt + 1}/{retries}")
                time.sleep(delay)  # Wait before retrying
 
        if logsenabled:
            break  # Exit the outer loop if a valid log is found
 
        current_start = current_end
 
    return logsenabled

# Example usage
from datetime import datetime,timedelta
start_time = datetime.utcnow() - timedelta(days=89)  # Adjust as needed
end_time = datetime.utcnow()

# Function to get the Bearer token
def get_access_token():
    token = credential.get_token("https://management.azure.com/.default")
    return token.token
 
# Function to get billing details for a subscription
def get_billing_details(subscription_id, billing_period, start_date, end_date, access_token):
    api_version = "2019-10-01"
    url = (f"https://management.azure.com/subscriptions/{subscription_id}/"
           f"providers/Microsoft.Billing/billingPeriods/{billing_period}/"
           f"providers/Microsoft.Consumption/usageDetails?api-version={api_version}")
    params = {
        '$filter': f"properties/usageEnd ge '{start_date}' AND properties/usageEnd le '{end_date}'"
    }
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {access_token}'
    }
    response = requests.get(url, headers=headers, params=params)
   
    if response.status_code != 200:
        logger.error(f"Error {response.status_code}: {response.text}")
        response.raise_for_status()
    return response.json()
 
# Function to determine if a subscription has no billing activity
def is_subscription_unused(billing_data):
    return len(billing_data.get('value', [])) == 0
 
# Function to get the current billing period
def get_current_billing_period():
    import datetime
    today = datetime.datetime.utcnow()
    return today.strftime('%Y-%m')

#function for get nsg associated with vm subsnet  
def get_vm_subnet_nsg(resource_group_name, vm_name, network_client, compute_client):
    """Get the NSG associated with the subnet of the VM."""
    vm = compute_client.virtual_machines.get(resource_group_name, vm_name)
    nic_id = vm.network_profile.network_interfaces[0].id
    nic_name = nic_id.split('/')[-1]
    nic = network_client.network_interfaces.get(resource_group_name, nic_name)
 
    # Assuming the primary IP configuration is the first one
    ip_config = nic.ip_configurations[0]
    subnet_id = ip_config.subnet.id
    subnet_name = subnet_id.split('/')[-1]
    vnet_name = subnet_id.split('/')[-3]
    vnet_resource_group = subnet_id.split('/')[4]
 
    subnet = network_client.subnets.get(vnet_resource_group, vnet_name, subnet_name)
 
    if not subnet.network_security_group:
        return None
    nsg_id = subnet.network_security_group.id
    nsg_name = nsg_id.split('/')[-1]
    nsg_resource_group = nsg_id.split('/')[4]
    return network_client.network_security_groups.get(nsg_resource_group, nsg_name)
 

def get_network_watcher(region, network_client):
    """Get the Network Watcher for the specified region."""
    network_watchers = network_client.network_watchers.list_all()
    for watcher in network_watchers:
        if watcher.location == region:
            return watcher
    return None
 
# function to check nsg flow logs   
def check_nsg_flow_logs(nsg, network_watcher, network_client):
    """Check if flow logs are enabled for the NSG and retrieve the storage account details."""
    flow_log_status = network_client.network_watchers.begin_get_flow_log_status(
        resource_group_name=network_watcher.id.split('/')[4],
        network_watcher_name=network_watcher.name,
        parameters={'target_resource_id': nsg.id}
    ).result()
    if flow_log_status.storage_id is not None and flow_log_status.storage_id:
        return flow_log_status.storage_id
    return None

# function check nsg flow logs under the storage account  
def check_storage_account_logs(storage_account_id, nsg, subscription_id, resource_group_name, credential):
    """Check the storage account for logs related to the specific NSG in the 'insights-logs-networksecuritygroupflowevent' container."""
    storage_account_name = storage_account_id.split('/')[-1]
    storage_resource_group_name = storage_account_id.split('/')[4]
    storage_subscription = storage_account_id.split('/')[2]
    storage_client = StorageManagementClient(credential, storage_subscription)
 
    # Get the storage account keys
    storage_keys = storage_client.storage_accounts.list_keys(storage_resource_group_name, storage_account_name)
    storage_key = storage_keys.keys[0].value
 
    # Create a blob service client
    blob_service_client = BlobServiceClient(account_url=f"https://{storage_account_name}.blob.core.windows.net", credential=storage_key)
 
    # Check the 'insights-logs-networksecuritygroupflowevent' container
    container_name = "insights-logs-networksecuritygroupflowevent"
    found_logs = False
    today = datetime.datetime.utcnow()
    start_date = today - datetime.timedelta(days=89)
 
    for month_diff in range(4):  # Check the last 3 months including the current month
        date_to_check = start_date + datetime.timedelta(days=30 * month_diff)
        year = date_to_check.year
        month = date_to_check.month
        blob_prefix = (
            f"resourceId=/SUBSCRIPTIONS/{subscription_id.upper()}/RESOURCEGROUPS/{resource_group_name.upper()}/PROVIDERS/MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/{nsg.name.upper()}/"
            f"y={year}/m={month:02d}/"
        )
 
        # List blobs with the specified prefix
        container_client = blob_service_client.get_container_client(container_name)
        blobs = container_client.list_blobs(name_starts_with=blob_prefix)
 
        for blob in blobs:
            found_logs = True
            logger.info(f"Log found: {blob.name} last modified on: {blob.last_modified}")
            break
        if found_logs:
            break
 
    if not found_logs:
        print(f"No logs found related to the NSG '{nsg.name}' in the last three months.")
    return found_logs  


def process_vm_nsg_and_flow_logs(subscription):
    logs_found = False
    compute_client = ComputeManagementClient(credential, subscription.subscription_id)
    network_client = NetworkManagementClient(credential, subscription.subscription_id)
    vms = compute_client.virtual_machines.list_all()

    for vm in vms:
        resource_group_name = vm.id.split('/')[4]
        vm_name = vm.name
        nsg = get_vm_subnet_nsg(resource_group_name, vm_name, network_client, compute_client)

        if nsg:
            region = vm.location
            network_watcher = get_network_watcher(region, network_client)
            if network_watcher:
                storage_account_id = check_nsg_flow_logs(nsg, network_watcher, network_client)
                if storage_account_id:
                    logs_found = check_storage_account_logs(storage_account_id, nsg, subscription.subscription_id, resource_group_name, credential)
                    if not logs_found:
                        print("flow logs found")
                else:
                    logger.info(f"No flow logs enabled for the NSG associated with the subnet of the VM '{vm_name}'.")
            else:
                logger.info(f"Network Watcher not found for the region '{region}'.")
        else:
            logger.info(f"No NSG associated with the VM '{vm_name}'.")

    return logs_found 

def main():
    billing_period = get_current_billing_period()
    import datetime
    end_time = datetime.datetime.utcnow()
    start_time = end_time - datetime.timedelta(days=89)
    start_date = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
    end_date = end_time.strftime('%Y-%m-%dT%H:%M:%SZ')
 
    access_token = get_access_token()
    unused_subscriptions = []
 
    try:
        subscription_client = SubscriptionClient(credential)
        user_input = sys.argv[1] if len(sys.argv) > 1 else "all"
 
        if user_input.lower() == "all":
            subscriptions = subscription_client.subscriptions.list()
        else:
            subscription_names = [s.strip() for s in user_input.split(",")]
            subscriptions = [s for s in subscription_client.subscriptions.list() if s.display_name in subscription_names]
            valid_subs, invalid_subs = subscriptions_validations.check_valid_subscription_names(subscription_names)
            if invalid_subs:
                logger.error(f"invalid input subscriptions {invalid_subs}")
        for subscription in subscriptions:
         try:
            logsenabled = check_activity_logs(subscription.subscription_id, subscription.display_name)
            billing_data = get_billing_details(subscription.subscription_id, billing_period, start_date, end_date, access_token)
            logs_found = process_vm_nsg_and_flow_logs(subscription)
            # 3 conditions checking like activty log "OR" Billing "AND" Flow Logs
            if not logsenabled or is_subscription_unused(billing_data) and not logs_found:
                resource_client = ResourceManagementClient(credential, subscription.subscription_id)
                subscription_tags = resource_client.tags.get_at_scope(f"/subscriptions/{subscription.subscription_id}")
                sub_tags = subscription_tags.properties.tags
                from datetime import datetime, timedelta
                cst_time = datetime.utcnow() - timedelta(hours=6)
                cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')

                unused_subscriptions.append({
                    'SubscriptionName': str(subscription.display_name),
                    'Subscription_ID': str(subscription.subscription_id),
                    'Sub_Tag': str(sub_tags) if sub_tags else "N/A",
                    'Timestamp': str(cst_time_str)
                    })
                logger.info(f"found unused subscription:{subscription.display_name}")
                 
         except Exception as e:
            logger.error(f"Failed to process subscription {subscription.display_name}: {str(e)}")
 
        #logger.info("Unused Subscriptions:", unused_subscriptions)
        df = pd.DataFrame(unused_subscriptions)
        table_name = 'azure_unused_subscriptions'
        columns = ['SubscriptionName','SubscriptionID','Sub_Tag', 'Timestamp']
        container_name = "azure-unused-subscriptions"
        if unused_subscriptions:
                notifications_email.send_email(container_name, container_name +' Data Report', "excel", container_name, df)
                Azure_SQL_Convertion.SQL_function(df, table_name, columns)
                Azure_Blob_Convertion.Blob_function(df, container_name, 'main_name')

    except Exception as e:
        logger.error(f"Failed to retrieve subscriptions: {str(e)}")
        # Retrieve logs from the handler
        all_logs = csv_error_handler.get_all_logs()
        error_logs = csv_error_handler.get_error_logs()
        # Save all logs and error logs to Blob Storage
        if all_logs:
            all_logs_df = pd.DataFrame(all_logs)
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-unused-subscriptions', 'all_logs')
            logger.info(f"All logs generated for CSV")
 
        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-unused-subscriptions', 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('azure-unused-subscriptions', 'azure-unused-subscriptions' +' Error Report', "excel", 'azure-unused-subscriptions', error_logs_df)
 
   
if __name__ == "__main__":
    main()