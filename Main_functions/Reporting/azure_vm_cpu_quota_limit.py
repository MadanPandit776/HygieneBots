import logging
import os
import sys
sys.path.append('.')
import pandas as pd
from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from datetime import datetime, timedelta
from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient
from azure.core.exceptions import HttpResponseError
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
 
 
# Define desired locations
desired_locations = ["eastus", "southcentralus", "uksouth", "germanywestcentral", "southeastasia", "australiaeast"]
 
def check_cpu_quota(subscription, credential):
    try:
        subscription_name = subscription.display_name
        subscription_id = subscription.subscription_id
        compute_client = ComputeManagementClient(credential, subscription_id)
        resource_client = ResourceManagementClient(credential, subscription_id)
        subscription_tags = resource_client.tags.get_at_scope(f"/subscriptions/{subscription_id}")
        sub_tags = subscription_tags.properties.tags
 
        quota_info = []
        # check above mentioned locations only
        for location in desired_locations:
            usages = compute_client.usage.list(location=location)
            # check Name only these two conditions if contains name "Standard" and "vCPUs"
            for usage in usages:
                if "Standard" in usage.name.localized_value and "vCPUs" in usage.name.localized_value:
                    quota_name = usage.name.localized_value
                    current_usage = usage.current_value
                    quota_limit = usage.limit
                    # check only greater that 0 value, not reuied if its 0 value 
                    if quota_limit > 0 and current_usage > 0:
                        remaining_quota_percentage = ((quota_limit - current_usage) / quota_limit) * 100
                        current_quota_utilization_percentage = (current_usage / quota_limit) * 100 
                        cst_time = datetime.utcnow() - timedelta(hours=6)
                        cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
                        #check greater than 80 percenatge quota limit 
                        if remaining_quota_percentage < 20:
                            quota_info.append({
                                'SubscriptionName': str(subscription_name),
                                'SubscriptionID': str(subscription_id),
                                'Region': location,
                                'Quota_Name': str(quota_name),
                                'Quota_Limit': str(quota_limit),
                                'Current_Usage': str(current_usage),
                                'Utilization_Quota_Percentage': f"{current_quota_utilization_percentage:.2f}%",
                                'Remaining_Quota_Percentage': f"{remaining_quota_percentage:.2f}%",
                                'Sub_Tag': str(sub_tags) if sub_tags else "N/A",
                                'Timestamp': str(cst_time_str)
                            })
                    logger.info(f"Azure VM CPU quota limit {quota_name} in subscription {subscription_name}")
 
        return quota_info
    except HttpResponseError as e:
        logging.error(f"HTTP error occurred during subscription {subscription.display_name} processing: {e}")
        return []
    except Exception as e:
        logging.error(f"An error occurred during subscription {subscription.display_name} processing: {e}")
        return []
 
def list_cpu_quota_info():
    try:
        # Initialize Azure credentials
        credential = DefaultAzureCredential()
        subscription_client = SubscriptionClient(credential)
 
        # Get user input for choice of subscriptions
        user_input = sys.argv[1] if len(sys.argv) > 1 else "all"
 
        if user_input.lower() == "all":
            subscriptions = subscription_client.subscriptions.list()
        else:
            subscription_names = [s.strip() for s in user_input.split(",")]
            subscriptions = [s for s in subscription_client.subscriptions.list() if s.display_name in subscription_names]
            valid_subs, invalid_subs = subscriptions_validations.check_valid_subscription_names(subscription_names)
            if invalid_subs:
                logger.error(f"Invalid input subscriptions: {invalid_subs}")
 
        quota_info_list = []
        with ThreadPoolExecutor() as executor:
            results = executor.map(lambda sub: check_cpu_quota(sub, credential), subscriptions)
            for result in results:
                quota_info_list.extend(result)
 
        # Create a DataFrame from the list of CPU quota information
        df = pd.DataFrame(quota_info_list)
        table_name = 'azure_vm_cpu_quota_limit'
       
        columns = ['SubscriptionName','SubscriptionID', 'Region', 'Quota_Name', 'Quota_Limit', 'Current_Usage','Utilization_Quota_Percentage','Remaining_Quota_Percentage','Sub_Tag', 'Timestamp']
        container_name = 'azure-vm-cpu-quota-limit'
        if quota_info_list:
            notifications_email.send_email(container_name, container_name + ' Data Report', "excel", container_name, df)
            Azure_SQL_Convertion.SQL_function(df, table_name, columns)
            Azure_Blob_Convertion.Blob_function(df, container_name, 'main_name')
 
    except Exception as e:
        logging.error(f"Error occurred: {e}")
    finally:
        # Retrieve logs from the handler
        all_logs = csv_error_handler.get_all_logs()
        error_logs = csv_error_handler.get_error_logs()
        # Save all logs and error logs to Blob Storage
        if all_logs:
            all_logs_df = pd.DataFrame(all_logs)
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-vm-cpu-quota-limit', 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-vm-cpu-quota-limit', 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('azure-vm-cpu-quota-limit', 'azure-vm-cpu-quota-limit' +' Error Report', "excel", 'azure-vm-cpu-quota-limit', error_logs_df)

 
if __name__ == "__main__":
    list_cpu_quota_info()
