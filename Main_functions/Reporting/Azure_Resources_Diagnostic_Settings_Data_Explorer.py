import logging
from azure.identity import DefaultAzureCredential
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.subscription import SubscriptionClient
import pandas as pd
import os
import sys
from concurrent.futures import ThreadPoolExecutor
sys.path.append('.')
from datetime import datetime, timedelta
from Class.Report_handler import Azure_SQL_Convertion
from Class.Report_handler import Azure_Blob_Convertion
from Class.Logging.csv_error_handler import CSVErrorHandler
from Class.Email import notifications_email

# Create lists to store logs
all_logs = []
error_logs = []

# Instantiate the handler
csv_error_handler = CSVErrorHandler()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(csv_error_handler)

def process_resource(resource, excluded_event_hubs, monitor_client, subscription_display_name, subscription_id, resource_group_name, data):
    try:
        if resource.location.lower() in ['eastus', 'southcentralus', 'uksouth', 'germanywestcentral', 'southeastasia', 'australiaeast']:

         logger.info(f"Processing resource: {resource.name} in {resource_group_name}")

         if resource.name not in excluded_event_hubs:
            resource_id = resource.id
            cluster_name = resource.name
            cluster_location = resource.location
            diagnostic_settings = monitor_client.diagnostic_settings.list(resource_id)
            has_diagSetByAzPolicyEventHub = False
            for setting in diagnostic_settings:
                if setting.name == "diagSetByAzPolicyEventHub":
                    cst_time = datetime.utcnow() - timedelta(hours=6)
                    cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
                    has_diagSetByAzPolicyEventHub = True
                    metric_status = False
                    succeeded_ingestion = False
                    failed_ingestion = False
                    ingestion_batching = False
                    command_list = False
                    query_list = False
                    table_list = False
                    table_det_list = False
                    journal_list = False
                    eventhub_enabled = "Not Found"
                    for metric in setting.metrics:
                        if metric.enabled:
                            metric_status = True
                    for log in setting.logs:
                        if log.category == 'SucceededIngestion':
                            succeeded_ingestion = log.enabled
                        elif log.category == 'FailedIngestion':
                            failed_ingestion = log.enabled
                        elif log.category == 'IngestionBatching':
                            ingestion_batching = log.enabled
                        elif log.category == 'Command':
                            command_list = log.enabled
                        elif log.category == 'Query':
                            query_list = log.enabled
                        elif log.category == 'TableUsageStatistics':
                            table_list = log.enabled
                        elif log.category == 'TableDetails':
                            table_det_list = log.enabled
                        elif log.category == 'Journal':
                            journal_list = log.enabled
                    if setting.event_hub_authorization_rule_id is not None:
                        eventhub_enabled = "Found"

                    # Append data to the list
                    data.append({
                        'SubscriptionName': str(subscription_display_name),
                        'SubscriptionID': str(subscription_id),
                        'RG_Name': str(resource_group_name),
                        'Location': str(cluster_location),
                        'Data_Explorer_Cluster_Name': str(cluster_name),
                        'Metric_Status': str(metric_status),
                        'SucceededIngestion': str(succeeded_ingestion),
                        'FailedIngestion': str(failed_ingestion),
                        'IngestionBatching': str(ingestion_batching),
                        'Command_list': str(command_list),
                        'Query_list': str(query_list),
                        'Table_list': str(table_list),
                        'Table_det_list': str(table_det_list),
                        'Journal_list': str(journal_list),
                        'DiagSetByAzPolicyEventHub': str(eventhub_enabled),
                        'Timestamp': str(cst_time_str)
                    })
                    # Log data append operation
                    logger.info(f"Process for resource: {resource.name}")
                    # No need to check other diagnostic settings once "diagSetByAzPolicyEventHub" is found
                    break

            # If "diagSetByAzPolicyEventHub" diagnostic setting not found for the resource, include it in the report
            if not has_diagSetByAzPolicyEventHub:
                cst_time = datetime.utcnow() - timedelta(hours=6)
                cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
                data.append({
                        'SubscriptionName': str(subscription_display_name),
                        'SubscriptionID': str(subscription_id),
                        'RG_Name': str(resource_group_name),
                        'Location': str(cluster_location),
                        'Data_Explorer_Cluster_Name': str(cluster_name),
                        'Metric_Status': "Not Found",
                        'SucceededIngestion': "Not Found",
                        'FailedIngestion': "Not Found",
                        'IngestionBatching': "Not Found",
                        'Command_list': "Not Found",
                        'Query_list': "Not Found",
                        'Table_list': "Not Found",
                        'Table_det_list': "Not Found",
                        'Journal_list': "Not Found",
                        'DiagSetByAzPolicyEventHub': "Not Found",
                        'Timestamp': str(cst_time_str)
                })
                # Log data append operation
                logger.info(f"Process for resource: {resource.name}")
    except Exception as e:
        logger.error(f"Error processing resource: {resource.name}. Error: {str(e)}")

def generate_azure_data_explorer_resources_report():
    try:
        # Define resource types
        resource_types = {
            "DataExplorerCluster": "Microsoft.Kusto/clusters"
        }

        credential = DefaultAzureCredential()
        #credential = DefaultAzureCredential(exclude_managed_identity_credential=True)
        subscription_client = SubscriptionClient(credential)

       
        subscription_rg_map = {}
        # Parse environment variables for subscription to resource group mappings
        for key, value in os.environ.items():
         if key.startswith('SUBSCRIPTION_RG_MAP_'):
          subscription_id, rgs = value.split(':')
          resource_groups = rgs.split(',')
          subscription_rg_map[subscription_id] = resource_groups

        print(subscription_rg_map)
        excluded_event_hubs = ["pep-itom-shared-eus-01-ehns", "pep-itom-shared-scus-01-ehns","pep-itom-shared-suk-01-ehns","pep-itom-shared-gwc-01-ehns","pep-itom-shared-sea-01-ehns","pep-itom-shared-ae-01-ehns"]

        with ThreadPoolExecutor(max_workers=10) as executor:
            data = []  # Initialize data list here

            for subscription_id, resource_groups in subscription_rg_map.items():
                subscription = subscription_client.subscriptions.get(subscription_id)
                logger.info(f"Processing subscription: {subscription.display_name}")
                res_client = ResourceManagementClient(credential, subscription_id)
                monitor_client = MonitorManagementClient(credential, subscription_id)

                for resource_group_name in resource_groups:
                    for service, resource_type in resource_types.items():
                        resources = res_client.resources.list_by_resource_group(resource_group_name, filter=f"resourceType eq '{resource_type}'")
                        futures = [executor.submit(process_resource, resource, excluded_event_hubs, monitor_client, subscription.display_name, subscription_id, resource_group_name, data) for resource in resources]

                        # Wait for all futures to complete
                        for future in futures:
                            future.result()

        # Convert data to DataFrame
        df = pd.DataFrame(data)
        table_name = 'Azure_Resources_Diagnostic_Settings_Data_Explorer'
        container_name = 'azure-resources-diagnostic-settings-data-explorer'
        columns = ['SubscriptionName', 'SubscriptionID', 'RG_Name', 'Location', 'Data_Explorer_Cluster_Name','Metric_Status','SucceededIngestion','FailedIngestion','IngestionBatching','Command_list','Query_list','Table_list','Table_det_list','Journal_list','DiagSetByAzPolicyEventHub','Timestamp']
        if data: 
         Azure_SQL_Convertion.SQL_function(df, table_name, columns)
         Azure_Blob_Convertion.Blob_function(df, container_name, 'main_name')
         notifications_email.send_email(container_name, container_name +' Data Report', "excel", container_name, df)


    except Exception as e:
        logger.error(f"Error generating Azure resources report: {str(e)}")
    finally:
        # Retrieve logs from the handler
        all_logs = csv_error_handler.get_all_logs()
        error_logs = csv_error_handler.get_error_logs()
        # Save all logs and error logs to Blob Storage
        if all_logs:
            all_logs_df = pd.DataFrame(all_logs)
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-resources-diagnostic-settings-data-explorer', 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-resources-diagnostic-settings-data-explorer', 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('Exception log file generated', 'azure-resources-diagnostic-settings-data-explorer' +' Exception Report', "excel", 'azure-resources-diagnostic-settings-data-explorer', error_logs_df)


