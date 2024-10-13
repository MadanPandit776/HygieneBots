import os
import sys
import pandas as pd
import logging
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.storage import StorageManagementClient
from concurrent.futures import ThreadPoolExecutor
from azure.mgmt.storage.models import BlobServiceProperties, DeleteRetentionPolicy
from datetime import datetime, timedelta
sys.path.append('.')
from Class.Report_handler import Azure_SQL_Convertion
from Class.Report_handler import Azure_Blob_Convertion
from Class.Logging.csv_error_handler import CSVErrorHandler
from Class.Email import notifications_email
from Class.Logging import subscriptions_validations
# Create lists to store logs
all_logs = []
error_logs = []

csv_error_handler = CSVErrorHandler()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(csv_error_handler)

def process_subscription(subscription, credential):
    try:
        storage_client = StorageManagementClient(credential, subscription.subscription_id)
        storage_accounts = storage_client.storage_accounts.list()

        soft_delete_status = []

        for storage_account in storage_accounts:
            storage_account_name = storage_account.name
            location = storage_account.location
            resource_group = storage_account.id.split('/')[4]
            blob_service_properties = storage_client.blob_services.list(resource_group, storage_account_name)

            for blob_service in blob_service_properties:
                blob_service_name = blob_service.name
                cst_time = datetime.utcnow() - timedelta(hours=6)
                cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')

                if blob_service.delete_retention_policy.enabled and blob_service.delete_retention_policy.days < 30:
                    retention_days = blob_service.delete_retention_policy.days 
                    soft_delete_status.append({
                        'SubscriptionName': str(subscription.display_name),
                        'Subscription': str(subscription.subscription_id),
                        'StorageAccountName': str(storage_account_name),
                        'storageLocation': str(location),
                        'SoftDeleteRetentionPolicyEnabled': str(True),
                        'RetentionDays': str(retention_days),
                        'Timestamp': str(cst_time_str)
                    })
                    logger.info(f"Blob soft delete retention period : {storage_account_name} in subscription {subscription.display_name}")

                if not blob_service.delete_retention_policy.enabled:
                      soft_delete_status.append({
                        'SubscriptionName': str(subscription.display_name),
                        'Subscription': str(subscription.subscription_id),
                        'StorageAccountName': str(storage_account_name),
                        'storageLocation': str(location),
                        'SoftDeleteRetentionPolicyEnabled': str(False),
                        'RetentionDays': "None",
                        'Timestamp': str(cst_time_str)
                    })  

                      logger.info(f"Blob soft delete retention period : {storage_account_name} in subscription {subscription.display_name}")
                # elif not blob_service.delete_retention_policy.enabled:
                #     retention_days = 7
                #     retention_policy = DeleteRetentionPolicy(enabled=True, days=retention_days)
                #     blob_service_properties = BlobServiceProperties(delete_retention_policy=retention_policy)
                #     storage_client.blob_services.set_service_properties(resource_group, storage_account_name, blob_service_properties)

                #     soft_delete_status.append({
                #         'Account': str(subscription.display_name),
                #         'Subscription': str(subscription.subscription_id),
                #         'StorageAccountName': str(storage_account_name),
                #         'Location': str(location)
                #      
                #         'SoftDeleteRetentionPolicyEnabled': True,
                #         'RetentionDays': str(retention_days),
                #         'Time_Zone': str(cst_time_str)
                #     })

        return soft_delete_status

    except Exception as e:
        logger.error(f"An error occurred during subscription {subscription.display_name} in {storage_account_name} : {e}")
        return []

def get_blob_storage_soft_delete_status():
    try:
        credential = DefaultAzureCredential()
        #credential = DefaultAzureCredential(exclude_managed_identity_credential=True)
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

        soft_delete_status = []

        with ThreadPoolExecutor() as executor:
            results = executor.map(lambda sub: process_subscription(sub, credential), subscriptions)
            for result in results:
                soft_delete_status.extend(result)

        df = pd.DataFrame(soft_delete_status)
        # Save results to Azure SQL and Blob Storage
        table_name = 'azure_blob_storage_soft_delete_retention_period_status'
        container_name = 'azure-blob-storage-soft-delete-retention-period-status'
        columns = ['SubscriptionName', 'Subscription', 'StorageAccountName', 'StorageLocation', 'SoftDeleteRetentionPolicyStatus','RetentionDays', 'Timestamp']
        if soft_delete_status: 
         Azure_SQL_Convertion.SQL_function(df, table_name, columns)
         Azure_Blob_Convertion.Blob_function(df, container_name, 'main_name')
         notifications_email.send_email(container_name, container_name +' Data Report', "excel", container_name, df)

    except Exception as e:
        logger.error(f"An error occurred: {e}")
    finally:
        # Retrieve logs from the handler
        all_logs = csv_error_handler.get_all_logs()
        error_logs = csv_error_handler.get_error_logs()
        # Save all logs and error logs to Blob Storage
        if all_logs:
            all_logs_df = pd.DataFrame(all_logs)
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-blob-storage-soft-delete-retention-period-status', 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-blob-storage-soft-delete-retention-period-status', 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('Exception log file generated', 'azure-blob-storage-soft-delete-retention-period-status' +' Exception Report', "excel", 'azure-blob-storage-soft-delete-retention-period-status', error_logs_df)

if __name__ == "__main__":
    get_blob_storage_soft_delete_status()
