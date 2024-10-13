import os
import pandas as pd
from datetime import datetime, timezone, timedelta
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.compute import ComputeManagementClient
import sys
import logging
sys.path.append('.')
from concurrent.futures import ThreadPoolExecutor
from Class.Report_handler import Azure_SQL_Convertion
from Class.Report_handler import Azure_Blob_Convertion
from Class.Logging.csv_error_handler import CSVErrorHandler
from Class.Email import notifications_email
from Class.Logging import subscriptions_validations

# Create lists to store logs
all_logs = []
error_logs = []

# Instantiate the handler
csv_error_handler = CSVErrorHandler()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(csv_error_handler)


def process_subscription(subscription):
    results = []
    try:
        credential = DefaultAzureCredential()
        #credential = DefaultAzureCredential(exclude_managed_identity_credential=True)
        subscription_id = subscription.subscription_id
        logger.info(f"Processing subscription: {subscription.display_name} (ID: {subscription_id})")
        compute_client = ComputeManagementClient(credential, subscription_id)
        for vm in compute_client.virtual_machines.list_all():
            try:
                array = vm.id.split("/")
                resource_group = array[4]
                vm_name = array[-1]
                statuses = compute_client.virtual_machines.instance_view(resource_group, vm_name).statuses
                status = len(statuses) >= 2 and statuses[1]
                if status and status.code == 'PowerState/stopped':
                    # Retrieve the last time the VM was stopped
                    last_stopped_time = statuses[0].time if hasattr(statuses[0], 'time') else None
                    if last_stopped_time:
                     last_stopped_time_str = last_stopped_time.strftime('%Y-%m-%d %H:%M:%S UTC')
                    cst_time = datetime.utcnow() - timedelta(hours=6)
                    cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
                    last_stopped_time = statuses[0].time
                    current_time = datetime.now(timezone.utc)
                    time_stopped = current_time - last_stopped_time
                    days_stopped = time_stopped.days
                    vm_tags = ", ".join(f"{key}: {value}" for key, value in vm.tags.items()) if vm.tags else ""

                    results.append({
                        "SubscriptionName": str(subscription.display_name),
                        "Subscription": str(subscription.subscription_id),
                        "ResourceGroup": str(resource_group),
                        "VirtualMachineName": str(vm.name),
                        "VM_Location": str(vm.location),
                        "Ostype": str(vm.storage_profile.os_disk.os_type),
                        "DaysStopped": str(days_stopped),
                        "VM_Stopped_Time":str(last_stopped_time_str),
                        "DeallocatedState": str(status.code),
                        "VMTags": vm_tags,
                        'Timestamp': str(cst_time_str) 
                    })
                    logger.info(f"VM '{vm_name}' stopped days '{days_stopped}'.")
            except Exception as e:
                logger.error(f"Error processing VM '{vm_name}': {str(e)}")
                continue
    except Exception as ex:
        logger.error(f"Error occurred in subscription {subscription.display_name}: {str(ex)}")
    return results

try:
    # Initialize Azure credentials
    credential = DefaultAzureCredential()
    #credential = DefaultAzureCredential(exclude_managed_identity_credential=True)
    subscription_client = SubscriptionClient(credential)
    user_input = ' '.join(sys.argv[1:]) if len(sys.argv) > 1 else "all"
    
    if user_input.lower() == "all":
        subscriptions = subscription_client.subscriptions.list()
    else:
        subscription_names = [s.strip() for s in user_input.split(",")]
        subscriptions = [s for s in subscription_client.subscriptions.list() if s.display_name in subscription_names]
        valid_subs, invalid_subs = subscriptions_validations.check_valid_subscription_names(subscription_names)
        if invalid_subs:
              logger.error(f"invalid input subscriptions {invalid_subs}")
    
    results = []

    with ThreadPoolExecutor() as executor:
        # Process each subscription concurrently
        future_results = [executor.submit(process_subscription, subscription) for subscription in subscriptions]
        for future in future_results:
            results.extend(future.result())

    df = pd.DataFrame(results)
    table_name = 'azure_vm_stop_deallocated'
    container_name = 'azure-vm-stop-deallocated'
    columns = ['SubscriptionName', 'Subscription', 'ResourceGroup', 'VirtualMachineName', 'VM_Location', 'Ostype', 'DaysStopped', 'VM_Stopped_Time','DeallocatedState', 'VMTags', 'Timestamp']
    Azure_SQL_Convertion.SQL_function(df, table_name, columns)
    Azure_Blob_Convertion.Blob_function(df, container_name, 'main_name')
    notifications_email.send_email(container_name, container_name +' Data Report', "excel", container_name, df)


except Exception as ex:
    logger.error(f"An error occurred: {str(ex)}")

finally:
    # Retrieve logs from the handler
    all_logs = csv_error_handler.get_all_logs()
    error_logs = csv_error_handler.get_error_logs()
    # Save all logs and error logs to CSV
    if all_logs:
        all_logs_df = pd.DataFrame(all_logs)
        container_name = 'azure-vm-stop-deallocated'
        Azure_Blob_Convertion.Blob_function(all_logs_df, container_name, 'all_logs')
        logger.info(f"All logs generated for CSV")

    if error_logs:
        error_logs_df = pd.DataFrame(error_logs)
        container_name = 'azure-vm-stop-deallocated'
        Azure_Blob_Convertion.Blob_function(error_logs_df, container_name, 'error_logs')
        logger.info(f"Error logs generated for CSV")
        notifications_email.send_email('Exception log file generated', 'azure-vm-stop-deallocated' +' Exception Report', "excel", 'azure-vm-stop-deallocated', error_logs_df)

