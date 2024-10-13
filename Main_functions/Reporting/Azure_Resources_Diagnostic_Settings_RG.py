import logging
from azure.identity import DefaultAzureCredential
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.subscription import SubscriptionClient
import pandas as pd
import os
import sys
from datetime import datetime, timedelta
sys.path.append('.')
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

# Define your target locations
target_locations = ['eastus', 'southcentralus', 'uksouth', 'germanywestcentral', 'southeastasia', 'australiaeast']

def generate_azure_resources_report():
    try:
        # Define resource types
        resource_types = {
            "AppServiceEnvironments": "Microsoft.Web/hostingEnvironments",
            "AzureDigitalTwins": "Microsoft.DigitalTwins/digitalTwinsInstances",
            "AppServicePlans": "Microsoft.Web/serverfarms",
            "FunctionAPP": "Microsoft.Web/sites",
            "KeyVault": "Microsoft.KeyVault/vaults",
            "EventGridSystemTopic": "Microsoft.EventGrid/systemTopics",
            "EventHub": "Microsoft.EventHub/namespaces",
            "ServiceBus": "Microsoft.ServiceBus/namespaces",
            "CosmosDB": "Microsoft.DocumentDB/databaseAccounts",
            "IoT": "Microsoft.Devices/IotHubs",

        }

        credential = DefaultAzureCredential()
        #credential = DefaultAzureCredential(exclude_managed_identity_credential=True)
        subscription_client = SubscriptionClient(credential)

        excluded_event_hubs = ["pep-itom-shared-eus-01-ehns", "pep-itom-shared-scus-01-ehns","pep-itom-shared-suk-01-ehns","pep-itom-shared-gwc-01-ehns","pep-itom-shared-sea-01-ehns","pep-itom-shared-ae-01-ehns"]


        data = []
        subscription_rg_map = {}
        # Parse environment variables for subscription to resource group mappings
        for key, value in os.environ.items():
         if key.startswith('SUBSCRIPTION_RG_MAP_'):
          subscription_id, rgs = value.split(':')
          resource_groups = rgs.split(',')
          subscription_rg_map[subscription_id] = resource_groups

        # Iterate over subscriptions
        print(subscription_rg_map)
        for subscription_id, resource_groups in subscription_rg_map.items():
            subscription = subscription_client.subscriptions.get(subscription_id)
            logger.info(f"Processing subscription: {subscription.display_name}")
            res_client = ResourceManagementClient(credential, subscription_id)
            monitor_client = MonitorManagementClient(credential, subscription_id)

            for resource_group_name in resource_groups:
                for service, resource_type in resource_types.items():
                    resources = res_client.resources.list_by_resource_group(resource_group_name, filter=f"resourceType eq '{resource_type}'")
                    for resource in resources:
                        try:
                            if resource.location.lower() in ['eastus', 'southcentralus', 'uksouth', 'germanywestcentral', 'southeastasia', 'australiaeast']:
                             logger.info(f"Processing resource: {resource.name} in {resource_group_name}")
                             if service == "FunctionAPP":  # Filter only Function Apps
                                properties = resource.properties
                                if resource.kind == "functionapp,linux" or resource.kind == "functionapp":
                                    resource_id = resource.id
                                    diagnostic_settings = monitor_client.diagnostic_settings.list(resource_id)
                                    has_diagSetByAzPolicyEventHub = False
                                    for setting in diagnostic_settings:
                                        if setting.name == "diagSetByAzPolicyEventHub":
                                            resourceName = resource.name
                                            logger.info(f"Process for resource: {resourceName}")
                                            cst_time = datetime.utcnow() - timedelta(hours=6)
                                            cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
                                            has_diagSetByAzPolicyEventHub = True
                                            metrics_enabled = False
                                            logs_enabled = False
                                            stream_to_eventhub_enabled = "Not Found"
                                            for metric_setting in setting.metrics:
                                                if hasattr(metric_setting, 'enabled'):
                                                    if metric_setting.enabled:
                                                        metrics_enabled = True
                                            for log in setting.logs:
                                                if log.enabled:
                                                    logs_enabled = True
                                            if setting.event_hub_authorization_rule_id is not None:
                                                stream_to_eventhub_enabled = "Found"

                                            data.append({
                                                'SubscriptionName': str(subscription.display_name),
                                                'SubscriptionID': str(subscription_id),
                                                'RG_Name': str(resource_group_name),
                                                'Service_Type': str(service),
                                                'Resource_Name': str(resource.name),
                                                'Resource_Location': str(resource.location),
                                                'Diagnostic_Name': str(setting.name),
                                                'Logs': str(logs_enabled),
                                                'Metric_Status': str(metrics_enabled),
                                                'EventHub': str(stream_to_eventhub_enabled),
                                                'Timestamp': str(cst_time_str)
                                            })
                                            # Log data append operation
                                            
                                            # No need to check other diagnostic settings once "diagSetByAzPolicyEventHub" is found
                                            break

                                    # If "diagSetByAzPolicyEventHub" diagnostic setting not found for the resource, include it in the report
                                    if not has_diagSetByAzPolicyEventHub:
                                        resourceName = resource.name
                                        logger.info(f"Process for resource: {resourceName}")
                                        cst_time = datetime.utcnow() - timedelta(hours=6)
                                        cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
                                        data.append({
                                            'SubscriptionName': str(subscription.display_name),
                                            'SubscriptionID': str(subscription_id),
                                            'RG_Name': str(resource_group_name),
                                            'Service_Type': str(service),
                                            'Resource_Name': str(resource.name),
                                            'Resource_Location': str(resource.location),
                                            'Diagnostic_Name': "diagSetByAzPolicyEventHub",
                                            'Logs': "Not Found",
                                            'Metric_Status': "Not Found",
                                            'EventHub': "Not Found",
                                            'Timestamp': str(cst_time_str)
                                        })
                                        # Log data append operation
                                        

                             else:
                                if resource.name not in excluded_event_hubs:
                                    resource_id = resource.id
                                    diagnostic_settings = monitor_client.diagnostic_settings.list(resource_id)
                                    has_diagSetByAzPolicyEventHub = False
                                    for setting in diagnostic_settings:
                                        if setting.name == "diagSetByAzPolicyEventHub":
                                            resourceName = resource.name
                                            logger.info(f"Process for resource: {resourceName}")
                                            cst_time = datetime.utcnow() - timedelta(hours=6)
                                            cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
                                            has_diagSetByAzPolicyEventHub = True
                                            metrics_enabled = False
                                            logs_enabled = False
                                            stream_to_eventhub_enabled = "Not Found"
                                            for metric_setting in setting.metrics:
                                                if hasattr(metric_setting, 'enabled'):
                                                    if metric_setting.enabled:
                                                        metrics_enabled = True
                                            for log in setting.logs:
                                                if log.enabled:
                                                    logs_enabled = True
                                            if setting.event_hub_authorization_rule_id is not None:
                                                stream_to_eventhub_enabled = "Found"

                                            data.append({
                                                'SubscriptionName': str(subscription.display_name),
                                                'SubscriptionID': str(subscription_id),
                                                'RG_Name': str(resource_group_name),
                                                'Service_Type': str(service),
                                                'Resource_Name': str(resource.name),
                                                'Resource_Location': str(resource.location),
                                                'Diagnostic_Name': str(setting.name),
                                                'Logs': str(logs_enabled),
                                                'Metric_Status': str(metrics_enabled),
                                                'EventHub': str(stream_to_eventhub_enabled),
                                                'Timestamp': str(cst_time_str)
                                            })
                                            # Log data append operation
                                            
                                            # No need to check other diagnostic settings once "diagSetByAzPolicyEventHub" is found
                                            break

                                    # If "diagSetByAzPolicyEventHub" diagnostic setting not found for the resource, include it in the report
                                    if not has_diagSetByAzPolicyEventHub:
                                        cst_time = datetime.utcnow() - timedelta(hours=6)
                                        cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
                                        resourceName = resource.name
                                        logger.info(f"Process for resource: {resourceName}")
                                        data.append({
                                            'SubscriptionName': str(subscription.display_name),
                                            'SubscriptionID': str(subscription_id),
                                            'RG_Name': str(resource_group_name),
                                            'Service_Type': str(service),
                                            'Resource_Name': str(resource.name),
                                            'Resource_Location': str(resource.location),
                                            'Diagnostic_Name': "diagSetByAzPolicyEventHub",
                                            'Logs': "Not Found",
                                            'Metric_Status': "Not Found",
                                            'EventHub': "Not Found",
                                            'Timestamp': str(cst_time_str)
                                        })
                                        # Log data append operation
                                        
                        except Exception as e:
                            logger.error(f"Error processing resource: {resource.name}. Error: {str(e)}")

        # Convert data to DataFrame
        df = pd.DataFrame(data)
        table_name = 'Azure_Resources_Diagnostic_Settings_RG'
        container_name = 'azure-resources-diagnostic-settings-rg'
        columns = ['SubscriptionName', 'SubscriptionID', 'RG_Name', 'Service_Type', 'Resource_Name', 'Resource_Location','Diagnostic_Name','Logs','Metric_Status','EventHub','Timestamp']
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
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-resources-diagnostic-settings-rg', 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-resources-diagnostic-settings-rg', 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('Exception log file generated', 'azure-resources-diagnostic-settings-rg' +' Exception Report', "excel", 'azure-resources-diagnostic-settings-rg', error_logs_df)


