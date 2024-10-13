import os
import logging
import datetime
import pandas as pd
import sys
from datetime import datetime, timedelta
from azure.identity import DefaultAzureCredential
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.subscription import SubscriptionClient
from dateutil import parser
from concurrent.futures import ThreadPoolExecutor  # Import ThreadPoolExecutor
from azure.mgmt.resourcegraph import ResourceGraphClient
from azure.mgmt.resourcegraph.models import QueryRequest
sys.path.append('.')
from Class.Report_handler import Azure_SQL_Convertion
from Class.Report_handler import Azure_Blob_Convertion
from Class.Logging.csv_error_handler import CSVErrorHandler
from Class.Email import notifications_email
import requests
from Class.Logging import subscriptions_validations

# Create lists to store logs
all_logs = []
error_logs = []

# Instantiate the handler
csv_error_handler = CSVErrorHandler()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(csv_error_handler)

def resolve_spn_name(credential, spn_id):
    credentials = DefaultAzureCredential(exclude_managed_identity_credential=True)
    access_token = credentials.get_token('https://graph.microsoft.com/.default').token
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
        return None

def query_nsg_changes(correlation_id):
    credential = DefaultAzureCredential()
    resource_graph_client = ResourceGraphClient(credential)
    
    query = f"""
    resourcechanges
| extend changeTime = todatetime(properties.changeAttributes.timestamp),
         targetResourceId = tostring(properties.targetResourceId),
         changeType = tostring(properties.changeType),
         correlationId = tostring(properties.changeAttributes.correlationId),
         changeDetails = parse_json(tostring(properties.changes)),
         changedBy = tostring(properties.changeAttributes.changedBy)
| where correlationId == '{correlation_id}'
  and properties.targetResourceType =~ 'Microsoft.Network/networkSecurityGroups'
| mv-expand changeDetail = changeDetails
| extend propertyPath = tostring(bag_keys(changeDetail)[0]),
         changeValues = changeDetail[tostring(bag_keys(changeDetail)[0])]
| extend newValue = tostring(changeValues.newValue),
         previousValue = tostring(changeValues.previousValue),
         changeAction = changeValues.propertyChangeType
| where propertyPath !contains 'etag'  // Exclude etag changes
| where propertyPath !contains 'properties.provisioningState'  // Exclude provisioningState changes
| where propertyPath !contains '.id'  // Exclude resource ID changes
| summarize changeDetails = make_list(pack("propertyPath", propertyPath, "changeAction", changeAction, "newValue", newValue, "previousValue", previousValue)) by changeTime, targetResourceId, changeType, correlationId, changedBy
| project changeTime, targetResourceId, changeType, correlationId, changedBy, changeDetails

"""
    
    query_request = QueryRequest(
        subscriptions=[],  # Leave empty if not filtering by subscription
        query=query
    )
    
    response = resource_graph_client.resources(query_request)
    return response.data


def process_subscription(subscription, credential):
    data = []
    import datetime
    end_time = datetime.datetime.utcnow()
    start_time = end_time - datetime.timedelta(days=7)
    try:
        subscription_id = subscription.subscription_id
        subscription_name = subscription.display_name
        print(subscription_name)
        resource_client = ResourceManagementClient(credential, subscription_id)
        monitor_client = MonitorManagementClient(credential, subscription_id)

        for rg in resource_client.resource_groups.list():
            # Check for NSGs resources
            nsgs = resource_client.resources.list_by_resource_group(rg.name, filter="resourceType eq 'Microsoft.Network/networkSecurityGroups'")
            for nsg in nsgs:
                print(nsg.name)
                nsg_name = nsg.name
                nsg_location = nsg.location
                try:
                    activity_logs = monitor_client.activity_logs.list(
                        filter=f"eventTimestamp ge '{start_time.isoformat()}' and eventTimestamp le '{end_time.isoformat()}' and resourceUri eq '{nsg.id}'",
                        select='eventTimestamp,caller,operationName,status,resourceId,correlationId'
                    )
                    
                    # Append data to the list
                    for log in activity_logs:
                        from datetime import datetime, timedelta
                        correlation_id = log.correlation_id if hasattr(log, 'correlation_id') else None
                        cst_time = datetime.utcnow() - timedelta(hours=6)
                        cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
                        timestamp_str = str(log.event_timestamp)
                        timestamp = parser.parse(timestamp_str).replace(tzinfo=None)  # Convert to timezone-unaware datetime
                        caller_name = log.caller
                        operation_name = log.operation_name.localized_value if hasattr(log.operation_name, 'localized_value') else None
                        activity_status = getattr(log.status, 'value', None)
                        rule_id = log.resource_id
                        rule_name = rule_id.split('/')[-1]
                        
                        if activity_status == 'Succeeded':
                         nsg_changes = query_nsg_changes(correlation_id)
                         if hasattr(log, 'claims') and 'xms_mirid' in log.claims:
                            xms_mirid = log.claims['xms_mirid']
                            mi_name = xms_mirid.rsplit('/', 1)[-1]
                            change_details = [change['changeDetails'] for change in nsg_changes if change['changeType'] == 'Update']
                            if change_details:
                                data.append({
                                    'SubscriptionName': subscription.display_name,
                                    'Subscription': subscription_id,
                                    'ResourceGroupName': rg.name,
                                    'NSGName': nsg_name,
                                    'NSG_Region': nsg_location,
                                    'NSGChangedBy': mi_name,
                                    'NSGChangeMadeOn': str(timestamp),
                                    'NSGChangeType': operation_name,
                                    'NSGRule_Name': rule_name,
                                    'Changes': str(change_details),
                                    'Timestamp': cst_time_str 
                                })
                                logger.info(f"Found NSG change '{operation_name}' made by '{caller_name}' for NSG '{nsg_name}' in resource group '{rg.name}' in subscription '{subscription.display_name}'")
                         else:
                          principal_id_or_email = log.caller
                          change_details = [change['changeDetails'] for change in nsg_changes if change['changeType'] == 'Update']
                          if '@' in principal_id_or_email:
                            if change_details:
                                data.append({
                                    'SubscriptionName': subscription.display_name,
                                    'Subscription': subscription_id,
                                    'ResourceGroupName': rg.name,
                                    'NSGName': nsg_name,
                                    'NSG_Region': nsg_location,
                                    'NSGChangedBy': caller_name,
                                    'NSGChangeMadeOn': str(timestamp),
                                    'NSGChangeType': operation_name,
                                    'NSGRule_Name': rule_name,
                                    'Changes': str(change_details),
                                    'Timestamp': cst_time_str 
                                })
                                logger.info(f"Found NSG change '{operation_name}' made by '{caller_name}' for NSG '{nsg_name}' in resource group '{rg.name}' in subscription '{subscription.display_name}'")

                          else:
                            if change_details: 
                                principal_name = resolve_spn_name(credential, principal_id_or_email)
                                data.append({
                                    'SubscriptionName': subscription.display_name,
                                    'Subscription': subscription_id,
                                    'ResourceGroupName': rg.name,
                                    'NSGName': nsg_name,
                                    'NSG_Region': nsg_location,
                                    'NSGChangedBy': principal_name,
                                    'NSGChangeMadeOn': str(timestamp),
                                    'NSGChangeType': operation_name,
                                    'NSGRule_Name': rule_name,
                                    'Changes': str(change_details),
                                    'Timestamp': cst_time_str })
                                logger.info(f"Found NSG change '{operation_name}' made by '{caller_name}' for NSG '{nsg_name}' in resource group '{rg.name}' in subscription '{subscription.display_name}'")
                except Exception as e:
                    logger.error(f"Failed to process NSG {nsg_name} in subscription {subscription.display_name}: {e}")
                    continue
    except Exception as subscription_loop_exception:
        logger.error(f"An error occurred during subscription loop: {subscription_loop_exception}")
        return []

    return data

def track_nsg_changes():
    try:
        # Initialize Azure credentials
        #credential = DefaultAzureCredential(exclude_managed_identity_credential=True)
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
              logger.error(f"invalid input subscriptions {invalid_subs}")

        with ThreadPoolExecutor() as executor:
            # Process each subscription concurrently    
            results = executor.map(lambda sub: process_subscription(sub, credential), subscriptions)
            for result in results:
                data.extend(result)

        # Create DataFrame from the data
        df = pd.DataFrame(data)
        table_name = 'azure_nsg_seven_days_modification_track_changes'
        container_name = 'azure-nsg-seven-days-modification-track-changes'
        columns = ['SubscriptionName', 'Subscription','ResourceGroupName', 'NSGName', 'NSG_Region', 'NSGChangedBy','NSGChangeMadeOn','NSGChangeType','NSGRule_Name','Changes','Timestamp']
        if data:
         Azure_SQL_Convertion.SQL_function(df, table_name, columns)
         Azure_Blob_Convertion.Blob_function(df, container_name, 'main_name')
         notifications_email.send_email(container_name, container_name +' Data Report', "excel", container_name, df)


    except Exception as e:
        logger.error(f"An error occurred: {e}")

    finally:
        all_logs = csv_error_handler.get_all_logs()
        error_logs = csv_error_handler.get_error_logs()
        # Save all logs and error logs to CSV
        if all_logs:
            all_logs_df = pd.DataFrame(all_logs)
            container_name = 'azure-nsg-seven-days-modification-track-changes'
            Azure_Blob_Convertion.Blob_function(all_logs_df, container_name, 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            container_name = 'azure-nsg-seven-days-modification-track-changes'
            Azure_Blob_Convertion.Blob_function(error_logs_df, container_name, 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('Exception log file generated', 'azure-nsg-seven-days-modification-track-changes' +' Exception Report', "excel", 'azure-nsg-seven-days-modification-track-changes', error_logs_df)


# Call the function
track_nsg_changes()
