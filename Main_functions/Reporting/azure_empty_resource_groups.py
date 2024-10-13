#azure_empty_resource_group.py
import os
import sys
sys.path.append('.')
import pandas as pd
import logging 
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.monitor import MonitorManagementClient
from datetime import datetime, timedelta
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
 
def process_subscription(subscription, credential):
    try:
        subscription_name = subscription.display_name
        subscription_id = subscription.subscription_id
        resource_client = ResourceManagementClient(credential, subscription_id)
        monitor_client = MonitorManagementClient(credential, subscription_id)
        empty_rg = []
 
        # Define the time window for the last 60 days
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=60)
        #start_time = end_time - timedelta(hours=4)

 
        subscription_tags = resource_client.tags.get_at_scope(f"/subscriptions/{subscription_id}")
        sub_tags = subscription_tags.properties.tags
        # List all Resource Groups
        resource_groups = resource_client.resource_groups.list()
        for rg in resource_groups:
            rg_name = rg.name
           
            # Check if the resource group has any resources
            resources = list(resource_client.resources.list_by_resource_group(rg_name))
           
            if not resources:
                # Query the activity log for the Resource Group
                activity_logs = monitor_client.activity_logs.list(
                    filter=f"eventTimestamp ge '{start_time.isoformat()}' and eventTimestamp le '{end_time.isoformat()}' and resourceGroupName eq '{rg_name}'"
                )
           
                # If no activity logs found for the resource group in the last 60 days
                if not list(activity_logs):
                    cst_time = datetime.utcnow() - timedelta(hours=6)
                    cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
   
                    empty_rg.append({
                        'SubscriptionName': str(subscription_name),
                        'SubscriptionId': str(subscription_id),
                        'ResourceGroupName': str(rg_name),
                        'Sub_Tag': str(sub_tags),
                        'Timestamp': str(cst_time_str)
                    })  
                    logger.info(f"Deleting empty resource group: {rg_name} in subscription: {subscription_id}")
                    # ----------Start----- Remidation for delete the resource group----------------
                    # resource_client.resource_groups.begin_delete(rg_name).result()
                    # ----------End----- Remidation for delete the resource group----------------
        return empty_rg
 
    except Exception as e:
        logger.error(f"An error occurred during subscription {subscription.display_name} processing: {e}")
        return []
 
def check_empty_resource_groups():
    try:
        credential = DefaultAzureCredential()
        subscription_client = SubscriptionClient(credential)
 
        user_input = sys.argv[1] if len(sys.argv) > 1 else "all"
 
        if user_input.lower() == "all":
            subscriptions = subscription_client.subscriptions.list()
        else:
            subscription_names = [s.strip() for s in user_input.split(",")]
            subscriptions = [s for s in subscription_client.subscriptions.list() if s.display_name in subscription_names]
 
        empty_rg_list = []
 
        with ThreadPoolExecutor() as executor:
            results = executor.map(lambda sub: process_subscription(sub, credential), subscriptions)
            for result in results:
                empty_rg_list.extend(result)
 
        df = pd.DataFrame(empty_rg_list)
        table_name = 'azure_empty_resource_groups'
        container_name = 'azure-empty-resource-groups'
        columns = ['SubscriptionName', 'SubscriptionId', 'ResourceGroupName', 'Sub_Tag', 'Timestamp']
        
        if empty_rg_list:
            Azure_SQL_Convertion.SQL_function(df, table_name, columns)
            Azure_Blob_Convertion.Blob_function(df, container_name, 'main_name')
            notifications_email.send_email(container_name, container_name +' Data Report', "excel", container_name, df)

       
    except Exception as e:
        logger.error(f"An error occurred during processing: {e}")
    finally:
        # Retrieve logs from the handler
        all_logs = csv_error_handler.get_all_logs()
        error_logs = csv_error_handler.get_error_logs()
        # Save all logs and error logs to Blob Storage
        if all_logs:
            all_logs_df = pd.DataFrame(all_logs)
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-empty-resource-groups', 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-empty-resource-groups', 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('azure-empty-resource-groups', 'azure-empty-resource-groups' +' Error Report', "excel", 'azure-empty-resource-groups', error_logs_df)


 
if __name__ == "__main__":
    check_empty_resource_groups()
