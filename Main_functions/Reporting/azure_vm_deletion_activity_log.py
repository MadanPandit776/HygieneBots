import pandas as pd
import sys
sys.path.append('.')
import logging
import concurrent
from datetime import datetime, timedelta
from azure.identity import DefaultAzureCredential
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.resource import SubscriptionClient
from concurrent.futures import ThreadPoolExecutor
from Class.Report_handler import Azure_SQL_Convertion
from Class.Report_handler import Azure_Blob_Convertion
from Class.Logging.csv_error_handler import CSVErrorHandler
from Class.Email import notifications_email
import requests

# Create lists to store logs
all_logs = []
error_logs = []
# Instantiate the handler
csv_error_handler = CSVErrorHandler()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(csv_error_handler)

deleted_resources = []

# Function to resolve SPN name using Microsoft Graph API
def resolve_spn_name(spn_id):
    credentials1 = DefaultAzureCredential(exclude_managed_identity_credential=True)
    access_token = credentials1.get_token('https://graph.microsoft.com/.default').token
    graph_api_endpoint = f'https://graph.microsoft.com/v1.0/servicePrincipals/{spn_id}'
    headers = {
        'Authorization': 'Bearer ' + access_token,
        'Content-Type': 'application/json'
    }
    
    response = requests.get(graph_api_endpoint, headers=headers)
    
    if response.status_code == 200:
        spn_details = response.json()
        spn_name = spn_details.get('displayName', 'Unknown SPN Name')
        return spn_name
    else:
        logger.error(f"Failed to retrieve SPN details. Status code: {response.text}")
        print(f"Failed to retrieve SPN details. Status code: {response.text}")
        return None

def fetch_deleted_resources(subscription):
    try:
        credential = DefaultAzureCredential()
        monitor_client = MonitorManagementClient(credential, subscription.subscription_id)

        activities = monitor_client.activity_logs.list(
            filter=f"eventTimestamp ge '{(datetime.now() - timedelta(days=1)).isoformat()}' and resourceType eq 'Microsoft.Compute/virtualMachines' ",
                  # "and operationName.value eq 'MICROSOFT.COMPUTE/VIRTUALMACHINES/DELETE'",
            select="eventTimestamp,resourceType,operationName,properties,caller,resourceId,status,resourceGroupName"
        )
        
        for activity in activities:
            resource_group = activity.resource_group_name
            # Exclude resource groups containing "databrick"
            if 'databrick' not in resource_group.lower() and 'citrix' not in resource_group.lower():
                operation_name = getattr(activity.operation_name, 'localized_value', None)
                activity_status = getattr(activity.status, 'value', None)
                resource_id = activity.resource_id
                initiated_time = activity.event_timestamp
                principal_id_or_email = activity.caller
                
                if operation_name == 'Delete Virtual Machine' and activity_status == 'Succeeded':
                    cst_time = datetime.utcnow() - timedelta(hours=6)
                    cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
                    if '@' in principal_id_or_email:  # Check if it's an email address
                        initiated_by = principal_id_or_email  # Use email directly
                    elif hasattr(activity, 'claims') and 'xms_mirid' in activity.claims:
                        xms_mirid = activity.claims['xms_mirid']
                        initiated_by = xms_mirid.rsplit('/', 1)[-1]
                    else:
                        initiated_by = resolve_spn_name(principal_id_or_email)
                    print(initiated_by)

                    deleted_resources.append({
                        'SubscriptionName': str(subscription.display_name),
                        'Subscription': str(subscription.subscription_id),
                        'Resource_Name': str(resource_id.split('/')[-1]),
                        'Initiated_Time': str(initiated_time.replace(tzinfo=None)),
                        'Initiated_By': str(initiated_by),
                        'ResourceGroup': str(resource_group),
                        'Operation_Name': str(operation_name),
                        'Time_Zone': str(cst_time_str)
                    })
                    logger.info(f"Process for resource: {resource_id.split('/')[-1]}")

        return deleted_resources

    except Exception as e:
        logger.error(f"Error occurred for subscription {subscription.subscription_id}: {e}")
        print(f"Error occurred for subscription {subscription.subscription_id}: {e}")
        return []

def list_create_and_delete_resources():
    try:
        credential = DefaultAzureCredential()
        subscription_client = SubscriptionClient(credential)
        user_input = ' '.join(sys.argv[1:]) if len(sys.argv) > 1 else "all"

        if user_input.lower() == "all":
            subscriptions = subscription_client.subscriptions.list()
        else:
            subscription_ids = [s.strip() for s in user_input.split(",")]
            subscriptions = [s for s in subscription_client.subscriptions.list() if s.subscription_id in subscription_ids]

        with concurrent.futures.ThreadPoolExecutor() as executor:
            deleted_resources = list(executor.map(fetch_deleted_resources, subscriptions))

        # Flatten the list of deleted resources
        deleted_resources_flat = [resource for sublist in deleted_resources for resource in sublist]

        # Only proceed if there are deleted resources
        if deleted_resources_flat:
            df = pd.DataFrame(deleted_resources_flat)
            table_name = 'azure_vm_deletion_activity_log'
            container_name = 'azure-vm-deletion-activity-log'
            columns = ['SubscriptionName', 'Subscription', 'Resource_Name', 'Initiated_Time', 'Initiated_By', 'ResourceGroup', 'Operation_Name', 'Time_Zone']
            
            Azure_SQL_Convertion.SQL_function(df, table_name, columns)
            Azure_Blob_Convertion.Blob_function(df, container_name, 'main_name')
            notifications_email.send_email(container_name, container_name + ' Data Report', "excel", container_name, df)
        else:
            logger.info("No deleted resources found.")

    except Exception as e:
        logger.error(f"Error occurred: {e}")
        print(f"Error occurred: {e}")

    finally:
        # Retrieve logs from the handler
        all_logs = csv_error_handler.get_all_logs()
        error_logs = csv_error_handler.get_error_logs()
        # Save all logs and error logs to Blob Storage
        if all_logs:
            all_logs_df = pd.DataFrame(all_logs)
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-vm-deletion-activity-log', 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-vm-deletion-activity-log', 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('Exception log file generated', 'azure-vm-deletion-activity-log' + ' Exception Report', "excel", 'azure-vm-deletion-activity-log', error_logs_df)



# Call the function to list deleted resources
list_create_and_delete_resources()
