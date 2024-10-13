import pandas as pd
import os
import sys
import logging
sys.path.append('.')
from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.resource import SubscriptionClient
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from azure.core.exceptions import ResourceNotFoundError  # Import specific exception
from Class.Report_handler import Azure_SQL_Convertion
from Class.Report_handler import Azure_Blob_Convertion
from Class.Logging.csv_error_handler import CSVErrorHandler
from Class.Email import notifications_email
from Class.Logging import subscriptions_validations

csv_error_handler = CSVErrorHandler()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(csv_error_handler)

def process_subscription(subscription, credential):
    snapshot_status = []
    compute_client = ComputeManagementClient(credential, subscription.subscription_id)
    subscription_name = subscription.display_name
    subscription_id = subscription.subscription_id

    for snapshot in compute_client.snapshots.list():
        snapshot_os_type = snapshot.os_type
        snapshot_name = snapshot.name
        snapshot_disk_type = snapshot.sku.name
        snapshot_tags = snapshot.tags if snapshot.tags else "N/A"
        source_disk = snapshot.creation_data.source_resource_id
        parts = source_disk.split('/')
        resource_group = parts[4]
        disk_name = parts[-1]

        try:
            disk = compute_client.disks.get(resource_group_name=resource_group, disk_name=disk_name)

            if not disk:
                print(f"Disk does not exist for snapshot: {snapshot_name}")
        except ResourceNotFoundError as not_found_error:
            if "Resource 'Microsoft.Compute/disks/" in str(not_found_error):
                cst_time = datetime.utcnow() - timedelta(hours=6)
                cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
                snapshot_created_on = snapshot.time_created.replace(tzinfo=None)
                days_since_creation = (datetime.utcnow() - snapshot_created_on).days

                snapshot_status.append({
                    "SubscriptionName": str(subscription_name),
                    "Subscription": str(subscription_id),
                    "ResourceGroup": str(resource_group),
                    "SnapshotId": str(snapshot_name),
                    "OSType": str(snapshot_os_type if snapshot_os_type else ""),
                    "SnapshotDiskType": str(snapshot_disk_type),
                    "SnapshotDiskSize": str(snapshot.disk_size_gb) if hasattr(snapshot, 'disk_size_gb') else "",  # Check if disk_size_gb is defined
                    "SourceDisk": str(disk_name),
                    "SnapshotCreatedOn": str(snapshot_created_on),  # Convert to string if necessary
                    "DaysSinceCreation": str(days_since_creation) if days_since_creation else "NA",
                    "Snapshot": str("orphan"),
                    "Tags": str(snapshot_tags),
                    "Timestamp": str(cst_time_str)
                })
                logger.info(f"Found Orphans Snapshot {snapshot_name} in subscription: {subscription_name}")

            else:
                pass  # Ignore other ResourceNotFoundError exceptions

        except Exception as e:
            logger.error(f"An unexpected error occurred: {str(e)}")

    return snapshot_status

def orphan_snapshots():
    try:
        # Initialize Azure credentials
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
                logger.error(f"invalid input subscriptions {invalid_subs}")

        snapshot_status = []

        with ThreadPoolExecutor() as executor:
            futures = {executor.submit(process_subscription, subscription, credential): subscription for subscription in subscriptions}

            for future in as_completed(futures):
                snapshot_status.extend(future.result())

        if snapshot_status:
            df = pd.DataFrame(snapshot_status)
            table_name = 'azure_orphans_snapshot'
            container_name = 'azure-orphans-snapshot'
            columns = ['SubscriptionName', 'Subscription', 'ResourceGroup', 'SnapshotId', 'OSType', 'SnapshotDiskType', 'SnapshotDiskSize', 'SourceDisk', 'SnapshotCreatedOn', 'DaysSinceCreation', 'Snapshot', 'Tags', 'Timestamp']
            
            # Assuming functions to handle SQL conversion and Blob upload exist in Azure_SQL_Convertion and Azure_Blob_Convertion modules
            Azure_SQL_Convertion.SQL_function(df, table_name, columns)
            Azure_Blob_Convertion.Blob_function(df, container_name, 'main_name')
            notifications_email.send_email(container_name, container_name + ' Data Report', "excel", container_name, df)

    except Exception as e:
        logger.error(f"An error occurred during subscription loop: {e}")

    finally:
        # Retrieve logs from the handler
        all_logs = csv_error_handler.get_all_logs()
        error_logs = csv_error_handler.get_error_logs()

        # Save all logs and error logs to Blob Storage if they exist
        if all_logs:
            all_logs_df = pd.DataFrame(all_logs)
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-orphans-snapshot', 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-orphans-snapshot', 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('Exception log file generated', 'azure-orphans-snapshot' +' Exception Report', "excel", 'azure-orphans-snapshot', error_logs_df)

# Execute the orphan snapshots processing
if __name__ == "__main__":
    orphan_snapshots()
