import logging
import os
import sys
sys.path.append('.')
import pandas as pd
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.storage import StorageManagementClient
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
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

# Define locations
desired_locations = ["eastus", "southcentralus", "uksouth", "germanywestcentral", "southeastasia", "australiaeast"]

# Function to fetch diagnostic settings for storage accounts
def fetch_diagnostic_settings(subscription, credential):
    storage_details = []
    try:
        subscription_id = subscription.subscription_id
        subscription_name = subscription.display_name
        #print(subscription_name)
        resource_client = ResourceManagementClient(credential, subscription_id)
        subscription_tags = resource_client.tags.get_at_scope(f"/subscriptions/{subscription_id}")
        sub_tags = subscription_tags.properties.tags
        storage_client = StorageManagementClient(credential, subscription_id)
        monitor_client = MonitorManagementClient(credential, subscription_id)
        storage_accounts = storage_client.storage_accounts.list()
       
        for storage_account in storage_accounts:
            storage_account_name = storage_account.name
            storage_account_id = storage_account.id
            storage_location = storage_account.location
            storage_account_location = storage_account.location
            resource_group = storage_account_id.split('/')[4]
            # check these 3 types only 'blob', 'queue', 'table'
            for service_type in ['blob', 'queue', 'table']:
                try:
                    diagnostic_settings = monitor_client.diagnostic_settings.list(
                        resource_uri=f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Storage/storageAccounts/{storage_account_name}/{service_type}Services/default"
                    )
                    setting_name = None
                    read_log = "False"
                    # check only these diagnostic names "bloblogging", "queuelogging",  "queueslogging", "tablelogging", "tableslogging"
                    for setting in diagnostic_settings:
                        if setting.name in ["bloblogging", "queuelogging",  "queueslogging", "tablelogging", "tableslogging"]: 
                            setting_name = setting.name
                            read_log = "True" if setting.logs else "False"
                        
                    cst_time = datetime.utcnow() - timedelta(hours=6)
                    cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
                    if storage_location in desired_locations:
                        storage_details.append({
                        'SubscriptionName': str(subscription_name),
                        'Subscription_ID': str(subscription_id),
                        'ResourceGroup': str(resource_group),
                        'StorageAccount': str(storage_account_name),
                        'StorageLocation': str(storage_account_location),
                        'ServiceType': service_type.capitalize(),
                        'DiagnosticName': str(setting_name),
                        'ReadLog': str(read_log),
                        'Sub_Tag': str(sub_tags) if sub_tags else "N/A",
                        'Timestamp': str(cst_time_str)
                    })
                    logger.info(f"Storage account logging disable  {storage_account_name} in subscription {subscription_name}")
                  
                except Exception as e:
                    logger.error(f"Error processing diagnostic settings for {storage_account_name} ({service_type}): {str(e)}")
    except Exception as e:
        logger.error(f"Error processing storage accounts for subscription {subscription_id}: {str(e)}")
    return storage_details
 
# Main function to get storage diagnostic settings
def get_storage_diagnostic_settings():
    try:
        # Initialize Azure credentials
        credential = DefaultAzureCredential()
        subscription_client = SubscriptionClient(credential)
 
        # Determine the subscriptions to process based on user input
        user_input = sys.argv[1] if len(sys.argv) > 1 else "all"
 
        if user_input.lower() == "all":
            subscriptions = subscription_client.subscriptions.list()
        else:
            subscription_names = [s.strip() for s in user_input.split(",")]
            subscriptions = [s for s in subscription_client.subscriptions.list() if s.display_name in subscription_names]
            valid_subs, invalid_subs = subscriptions_validations.check_valid_subscription_names(subscription_names)
            if invalid_subs:
                logger.error(f"invalid input subscriptions {invalid_subs}")

 
        all_storage_details = []
 
        # Use ThreadPoolExecutor to process subscriptions concurrently
        with ThreadPoolExecutor() as executor:
            results = executor.map(lambda sub: fetch_diagnostic_settings(sub, credential), subscriptions)
            for result in results:
                all_storage_details.extend(result)
 
        # Create DataFrame from the list of storage diagnostic settings
        df = pd.DataFrame(all_storage_details)
        table_name = 'azure_storage_account_logging_disabled'
        columns = ['SubscriptionName','Subscription_ID', 'ResourceGroup', 'StorageAccount', 'StorageLocation', 'ServiceType', 'DiagnosticName', 'ReadLog', 'Sub_Tag', 'Timestamp']
        container_name = 'azure-storage-account-logging-disabled'
        if all_storage_details:
            notifications_email.send_email(container_name, container_name +' Data Report', "excel", container_name, df)
            Azure_SQL_Convertion.SQL_function(df, table_name, columns)
            Azure_Blob_Convertion.Blob_function(df, container_name, 'main_name')
       
 
    except Exception as e:
        logger.error(f"An error occurred in the main function: {e}")
    finally:
        # Retrieve logs from the handler
        all_logs = csv_error_handler.get_all_logs()
        error_logs = csv_error_handler.get_error_logs()
        # Save all logs and error logs to Blob Storage
        if all_logs:
            all_logs_df = pd.DataFrame(all_logs)
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-storage-account-logging-disabled', 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-storage-account-logging-disabled', 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('azure-storage-account-logging-disabled', 'azure-storage-account-logging-disabled' +' Error Report', "excel", 'azure-storage-account-logging-disabled', error_logs_df)

 
if __name__ == "__main__":
    get_storage_diagnostic_settings()


