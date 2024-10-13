import os
import datetime
from dateutil import parser
import pandas as pd
from dateutil import parser
import logging
import sys
sys.path.append('.')
import requests
from azure.identity import DefaultAzureCredential
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.resourcegraph import ResourceGraphClient
from azure.mgmt.resourcegraph.models import QueryRequest
from concurrent.futures import ThreadPoolExecutor
from Class.Report_handler import Azure_SQL_Convertion, Azure_Blob_Convertion
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

# Function to resolve SPN name using Microsoft Graph API
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

def query_route_table_changes(correlation_id):
    credential = DefaultAzureCredential()
    resource_graph_client = ResourceGraphClient(credential)
    
    query = f"""resourcechanges
| extend changeTime = todatetime(properties.changeAttributes.timestamp),
         targetResourceId = tostring(properties.targetResourceId),
         changeType = tostring(properties.changeType),
         correlationId = tostring(properties.changeAttributes.correlationId),
         changeDetails = parse_json(tostring(properties.changes)),
         changedBy = tostring(properties.changeAttributes.changedBy)
| where correlationId == '{correlation_id}'
  and properties.targetResourceType =~ 'Microsoft.Network/routeTables'
| mv-expand changeDetail = changeDetails
| extend propertyPath = tostring(bag_keys(changeDetail)[0]),
         changeValues = changeDetail[tostring(bag_keys(changeDetail)[0])]
| extend newValue = tostring(changeValues.newValue),
         previousValue = tostring(changeValues.previousValue),
         changeAction = changeValues.propertyChangeType
| where propertyPath !contains 'etag'  // Exclude etag changes
| where propertyPath !contains '.id'  // Exclude resource ID changes
| where propertyPath !contains 'properties.provisioningState' or newValue == 'Succeeded'  // Exclude provisioningState changes except when newValue is Succeeded
| summarize changeDetails = make_list(pack("propertyPath", propertyPath, "changeAction", changeAction, "newValue", newValue, "previousValue", previousValue)) by changeTime, targetResourceId, changeType, correlationId, changedBy
| project changeTime, targetResourceId, changeType, correlationId, changedBy, changeDetails

"""
    
    query_request = QueryRequest(
        subscriptions=[],  # Leave empty if not filtering by subscription
        query=query
    )
    
    response = resource_graph_client.resources(query_request)
    return response.data

def process_subscription(subscription, start_time, end_time):
    data = []
    try:
        credential = DefaultAzureCredential()
        subscription_id = subscription.subscription_id
        subscription_name = subscription.display_name
        resource_client = ResourceManagementClient(credential, subscription_id)
        monitor_client = MonitorManagementClient(credential, subscription_id)

        for rg in resource_client.resource_groups.list():
            resources = resource_client.resources.list_by_resource_group(rg.name, filter="resourceType eq 'Microsoft.Network/routeTables'")
            for resource in resources:
                route_table_name = resource.name
                route_table_location = resource.location
                
                try:
                    activity_logs = monitor_client.activity_logs.list(
                        filter=f"eventTimestamp ge '{start_time}' and eventTimestamp le '{end_time}' and resourceUri eq '{resource.id}'",
                        select='eventTimestamp,caller,operationName,category,resourceId,status,correlationId,claims'
                    )
                     
                    for log in activity_logs:
                        route_id = log.resource_id
                        route_name = route_id.split('/')[-1]
                        correlation_id = log.correlation_id if hasattr(log, 'correlation_id') else None
                        operation_name = log.operation_name.localized_value if hasattr(log.operation_name, 'localized_value') else None
                        timestamp_str = str(log.event_timestamp)
                        timestamp = parser.parse(timestamp_str).replace(tzinfo=None)
                        activity_status = getattr(log.status, 'value', None)
                        print(correlation_id)
                        if activity_status == 'Succeeded' and correlation_id:
                            route_table_changes = query_route_table_changes(correlation_id)
                            cst_time = datetime.datetime.utcnow() - datetime.timedelta(hours=6)
                            cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')

                            if hasattr(log, 'claims') and 'xms_mirid' in log.claims:
                                xms_mirid = log.claims['xms_mirid']
                                mi_name = xms_mirid.rsplit('/', 1)[-1]
                                change_details = [change['changeDetails'] for change in route_table_changes if change['changeType'] == 'Update']
                                if change_details:
                                    data.append({
                                        'SubscriptionName': subscription.display_name,
                                        'Subscription': subscription_id,
                                        'ResourceGroupName': rg.name,
                                        'RouteTableName': resource.name,
                                        'RouteTable_Region': route_table_location,
                                        'Type': "Managed Identity",
                                        'RouteTableChangedBy': mi_name,
                                        'RouteTableChangeMadeOn': str(timestamp),
                                        'RouteTableChangeType': operation_name,
                                        'Changes': str(change_details),
                                        'Timestamp': cst_time_str
                                    })
                                    logger.info(f"Processing route table {route_table_name} in subscription {subscription.display_name}")
                            else:
                                principal_id_or_email = log.caller
                                if '@' in principal_id_or_email:
                                    principal_name = principal_id_or_email
                                else:
                                    principal_name = resolve_spn_name(credential, principal_id_or_email)

                                change_details = [change['changeDetails'] for change in route_table_changes if change['changeType'] == 'Update']
                                if change_details:
                                    data.append({
                                        'SubscriptionName': subscription.display_name,
                                        'Subscription': subscription_id,
                                        'ResourceGroupName': rg.name,
                                        'RouteTableName': resource.name,
                                        'RouteTable_Region': route_table_location,
                                        'RouteTableChangedBy': principal_name,
                                        'Type': "User" if '@' in principal_id_or_email else "SPN",
                                        'RouteTableChangeMadeOn': str(timestamp),
                                        'RouteTableChangeType': operation_name,
                                        'Changes': str(change_details),
                                        'Timestamp': cst_time_str
                                    })
                                    logger.info(f"Processing route table {route_table_name} in subscription {subscription.display_name}")
                except Exception as e:
                    logger.error(f"Error processing route table {route_table_name} in subscription {subscription.display_name}: {str(e)}")
    except Exception as e:
        logger.error(f"Error processing subscription {subscription.display_name}: {str(e)}")
        return []
    return data

def track_route_table_changes():
    try:
        credential = DefaultAzureCredential()
        subscription_client = SubscriptionClient(credential)
        data = []
        end_time = datetime.datetime.utcnow()
        start_time = end_time - datetime.timedelta(days=7)
        
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
            results = executor.map(lambda sub: process_subscription(sub, start_time, end_time), subscriptions)
            for result in results:
                data.extend(result)

        df = pd.DataFrame(data)
        table_name = 'azure_route_table_seven_days_modification_track_changes'
        container_name = 'azure-route-table-seven-days-modification-track-changes'
        columns = ['SubscriptionName', 'Subscription', 'ResourceGroupName', 'RouteTableName', 'RouteTable_Region', 'RouteTableChangedBy', 'Type', 'RouteTableChangeMadeOn', 'RouteTableChangeType', 'Changes', 'Timestamp']
        
        if data:
            Azure_SQL_Convertion.SQL_function(df, table_name, columns)
            Azure_Blob_Convertion.Blob_function(df, container_name, 'main_name')
            notifications_email.send_email(container_name, container_name + ' Data Report', "excel", container_name, df)
    except Exception as e:
        logger.error(f"Error in tracking route table changes: {str(e)}")
    finally:
        # Retrieve logs from the handler
        all_logs = csv_error_handler.get_all_logs()
        error_logs = csv_error_handler.get_error_logs()
        # Save all logs and error logs to CSV
        if all_logs:
            all_logs_df = pd.DataFrame(all_logs)
            container_name = 'azure-route-table-seven-days-modification-track-changes'
            Azure_Blob_Convertion.Blob_function(all_logs_df, container_name, 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            container_name = 'azure-route-table-seven-days-modification-track-changes'
            Azure_Blob_Convertion.Blob_function(error_logs_df, container_name, 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('Exception log file generated', 'azure-route-table-seven-days-modification-track-changes' +' Exception Report', "excel", 'azure-route-table-seven-days-modification-track-changes', error_logs_df)

       

if __name__ == "__main__":
    track_route_table_changes()
