import logging
import os
import datetime
import pandas as pd
import sys
sys.path.append('.')
import time
import random
from datetime import datetime, timedelta
from azure.identity import DefaultAzureCredential
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.subscription import SubscriptionClient
from dateutil import parser
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
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

# Function to resolve SPN name using Microsoft Graph API with retry logic
def resolve_spn_name(spn_id):
    credentials1 = DefaultAzureCredential(exclude_managed_identity_credential=True)
    access_token = credentials1.get_token('https://graph.microsoft.com/.default').token
    graph_api_endpoint = f'https://graph.microsoft.com/v1.0/servicePrincipals/{spn_id}'
    headers = {
        'Authorization': 'Bearer ' + access_token,
        'Content-Type': 'application/json'
    }

    max_retries = 5
    base_delay = 1  # Base delay in seconds

    for attempt in range(max_retries):
        try:
            response = requests.get(graph_api_endpoint, headers=headers)
            response.raise_for_status()
            spn_details = response.json()
            return spn_details.get('displayName', 'Unknown SPN Name')
        except requests.RequestException as e:
            if response.status_code == 429:  # Rate limit exceeded
                delay = base_delay * (2 ** attempt) + random.uniform(0, 1)
                logger.warning(f"Rate limit exceeded. Attempt {attempt + 1} of {max_retries}. Retrying in {delay:.2f} seconds.")
                time.sleep(delay)
            else:
                logger.error(f"Failed to retrieve SPN details: {e}")
                break

    logger.error("Failed to retrieve SPN details after multiple attempts.")
    return None

# Function to process each VM with rate-limiting handling
def process_vm(monitor_client, vm, subscription_name, subscription_id, rg_name, sub_tags, start_time, end_time):
    vm_name = vm.name
    vm_location = vm.location
    data = []
    # Get activity logs of VM and input passing vmID and time stamp from and to dates
    try:
        activity_logs = monitor_client.activity_logs.list(
            filter=f"eventTimestamp ge '{start_time.isoformat()}' and eventTimestamp le '{end_time.isoformat()}' and resourceUri eq '{vm.id}'",
            select='eventTimestamp,caller,operationName,status,resourceId,resourceGroupName'
        )
        #get the list of logs of that VM
        for log in activity_logs:
            if log.operation_name.localized_value == "Deallocate Virtual Machine":
                timestamp_str = str(log.event_timestamp)
                timestamp = parser.parse(timestamp_str).replace(tzinfo=None)
                log_date = timestamp.date()
                log_time = datetime.utcnow().date() - log_date

                # Check VM stopped more than 30 days
                if log_time.days > 29:
                    cst_time = datetime.utcnow() - timedelta(hours=6)
                    cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST')
                    caller_name = log.caller
                    operation_name = log.operation_name.localized_value if hasattr(log.operation_name, 'localized_value') else None
                    activity_status = getattr(log.status, 'value', None)
                    # Format the timestamp as a string with both date and time
                    timestamp_str_formatted = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                    if activity_status == 'Succeeded':
                        if '@' in caller_name:
                         initiated_by = caller_name
                        elif hasattr(log, 'claims') and 'xms_mirid' in log.claims:
                         xms_mirid = log.claims['xms_mirid']
                         initiated_by = xms_mirid.rsplit('/', 1)[-1]
                        else:
                         initiated_by = resolve_spn_name(caller_name)
                        data.append({
                            'SubscriptionName': str(subscription_name),
                            'SubscriptionID': str(subscription_id),
                            'VMName': str(vm_name),
                            'VMLocation': str(vm_location),
                            'VMStoppedBy': str(initiated_by),
                            'VMChangeMadeOn': timestamp_str_formatted,
                            'Sub_Tag': str(sub_tags),
                            'Time_Zone': str(cst_time_str)
                        })
                    logger.info(f"Found VM stop event '{operation_name}' made by '{caller_name}' for VM '{vm_name}' in resource group '{rg_name}' in subscription '{subscription_name}'")
    except requests.RequestException as e:
        if e.response and e.response.status_code == 429:
            logger.warning("Rate limit exceeded while processing VM. Retrying...")
            time.sleep(60)  # Wait for a minute before retrying
            return process_vm(monitor_client, vm, subscription_name, subscription_id, rg_name, sub_tags, start_time, end_time)
        else:
            logger.error(f"Failed to process VM {vm_name} in subscription {subscription_name}: {e}")
    except Exception as e1:
        logger.error(f"An error occurred: {e1}") 
    return data

def process_subscription(subscription, credential):
    data = []
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=30)

    try:
        subscription_id = subscription.subscription_id
        subscription_name = subscription.display_name
        resource_client = ResourceManagementClient(credential, subscription_id)
        subscription_tags = resource_client.tags.get_at_scope(f"/subscriptions/{subscription_id}")
        sub_tags = subscription_tags.properties.tags
        monitor_client = MonitorManagementClient(credential, subscription_id)
        
        for rg in resource_client.resource_groups.list():
            # Skip the rg's if name contains like databricks or citrix
            if 'databricks' not in rg.name and 'citrix' not in rg.name:
                vms = resource_client.resources.list_by_resource_group(rg.name, filter="resourceType eq 'Microsoft.Compute/virtualMachines'")

                with ThreadPoolExecutor() as vm_executor:
                    futures = [vm_executor.submit(process_vm, monitor_client, vm, subscription_name, subscription_id, rg.name, sub_tags, start_time, end_time) for vm in vms]
                    for future in as_completed(futures):
                        data.extend(future.result())

    except Exception as subscription_loop_exception:
        logger.error(f"An error occurred during subscription loop: {subscription_loop_exception}")
        return []

    return data

def track_vm_stops():
    try:
        credential = DefaultAzureCredential()
        subscription_client = SubscriptionClient(credential)

        data = []

        user_input = ' '.join(sys.argv[1:]) if len(sys.argv) > 1 else "all"
        if user_input.lower() == "all":
            subscriptions = subscription_client.subscriptions.list()
        else:
            subscription_names = [s.strip() for s in user_input.split(",")]
            subscriptions = [s for s in subscription_client.subscriptions.list() if s.display_name in subscription_names]
            valid_subs, invalid_subs = subscriptions_validations.check_valid_subscription_names(subscription_names)
            if invalid_subs:
                logger.error(f"Invalid input subscriptions {invalid_subs}")

        with ThreadPoolExecutor() as executor:
            results = executor.map(lambda sub: process_subscription(sub, credential), subscriptions)
            for result in results:
                data.extend(result)

        df = pd.DataFrame(data)
        table_name = 'azure_vm_deallocated_activity'
        columns = ['SubscriptionName', 'SubscriptionID', 'VMName', 'VMLocation', 'VMStoppedBy', 'VMChangeMadeOn', 'Sub_Tag', 'Time_Zone']
        container_name = 'azure-vm-deallocated-activity'

        if data:
            notifications_email.send_email(container_name, container_name + ' Data Report', "excel", container_name, df)
            Azure_SQL_Convertion.SQL_function(df, table_name, columns)
            Azure_Blob_Convertion.Blob_function(df, container_name, 'main_name')

    except Exception as e:
        logger.error(f"An error occurred: {e}")
    finally:
        all_logs = csv_error_handler.get_all_logs()
        error_logs = csv_error_handler.get_error_logs()
        if all_logs:
            all_logs_df = pd.DataFrame(all_logs)
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-vm-deallocated-activity', 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-vm-deallocated-activity', 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('azure-vm-deallocated-activity', 'azure-vm-deallocated-activity' + ' Error Report', "excel", 'azure-vm-deallocated-activity', error_logs_df)

# Call the function
track_vm_stops()
