import sys
from azure.identity import DefaultAzureCredential
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.subscription import SubscriptionClient
import pandas as pd
import os
import logging
import concurrent.futures
from datetime import datetime, timedelta
sys.path.append('.')
from Class.Report_handler import Azure_SQL_Convertion
from Class.Report_handler import Azure_Blob_Convertion
from Class.Logging.csv_error_handler import CSVErrorHandler
from Class.Email import notifications_email
from Class.Logging import subscriptions_validations


# Instantiate the handler
csv_error_handler = CSVErrorHandler()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(csv_error_handler)

all_logs = []
error_logs = []

# Define locations
desired_locations = ["eastus", "southcentralus", "uksouth", "germanywestcentral", "southeastasia", "australiaeast"]

# Define resource types
resource_types = {
    "LoadBalancers": "Microsoft.Network/loadBalancers",
    "AppGateway": "Microsoft.Network/applicationGateways",
    "AzureFrontDoor": "Microsoft.Cdn/profiles",
    "AKS": "Microsoft.ContainerService/managedClusters",
    "CacheRedis": "Microsoft.Cache/Redis",
    "AzureSQL": "Microsoft.Sql/servers/databases",
    "SingleServer": "Microsoft.DBforMySQL/servers",
    "FlexibleServer": "Microsoft.DBforMySQL/flexibleServers"
 }

def fetch_resource_diagnostic_settings(subscription_Name,subscription_id, service, resource, monitor_client):
    try:
        if resource.location.lower() in ['eastus', 'southcentralus', 'uksouth', 'germanywestcentral', 'southeastasia', 'australiaeast']:
         resource_id = resource.id
         diagnostic_settings = monitor_client.diagnostic_settings.list(resource_id)
         resourceName = resource.name
         has_diagSetByAzPolicyEventHub = False
         cst_time = datetime.utcnow() - timedelta(hours=6)
         cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
         for setting in diagnostic_settings:
            print(setting.name)
            if setting.name == "diagSetByAzPolicyEventHub":
                has_diagSetByAzPolicyEventHub = True
                metrics_enabled = any(getattr(metric_setting, 'enabled', False) for metric_setting in setting.metrics)
                logs_enabled = any(log.enabled for log in setting.logs)
                stream_to_eventhub_enabled = "Not Found" if setting.event_hub_authorization_rule_id is None else "Found"
                logger.info(f"Process for resource: {resourceName}")
                return {
                    'SubscriptionName': subscription_Name,
                    'SubscriptionID': subscription_id,
                    'Service_Type': service,
                    'Resource_Name': resource.name,
                    'Resource_Location': resource.location,
                    'Diagnostic_Name': setting.name,
                    'Logs': str(logs_enabled),
                    'Metric_Status': str(metrics_enabled),
                    'EventHub': str(stream_to_eventhub_enabled),
                    'Timestamp': cst_time_str
                }
                
                break
        # If "diagSetByAzPolicyEventHub" diagnostic setting not found for the resource, include it in the report
         if not has_diagSetByAzPolicyEventHub:
            logger.info(f"Process for resource: {resourceName}")
            return {
                'SubscriptionName': subscription_Name,
                'SubscriptionID': subscription_id,
                'Service_Type': service,
                'Resource_Name': resource.name,
                'Resource_Location': resource.location,
                'Diagnostic_Name': "diagSetByAzPolicyEventHub",
                'Logs': "Not Found",
                'Metric_Status': "Not Found",
                'EventHub': "Not Found",
                'Timestamp': cst_time_str
            }
    except Exception as e:
        logger.error(f"Error processing resource {resource.name}: {str(e)}")
        return None

def get_report_dig_settings_sub():


    # Authenticate Azure
    try:
        #credential = DefaultAzureCredential(exclude_managed_identity_credential=True)
        credential = DefaultAzureCredential()
        subscription_client = SubscriptionClient(credential)

        # List of subscription names
    #     subscription_names = [
    #     "pep-automation-01-sub",
    #     "pep-dr-automation-01-sub",
    #     "pep-pgt-automation-01-sub",
    #     "pep-nonprod-openai-dev-01-sub",
    #     "pep-nonprod-openai-dev-02-sub",
    #     "pep-nonprod-openai-qa-01-sub",
    #     "pep-nonprod-openai-qa-02-sub",
    #     "pep-prod-openai-01-sub",
    #     "pep-prod-openai-02-sub",
    #     "pep-dr-prod-snt-01-sub",
    #     "pep-dr-snt-mdip-01-sub",
    #     "pep-nonprod-snt-01-sub",
    #     "pep-nonprod-snt-mdip-01-sub",
    #     "pep-prod-snt-01-sub",
    #     "pep-prod-snt-mdip-01-sub",
    #     "pep-nonprod-ecomm-01-sub",
    #     "pep-prod-ecomm-01-sub",
    #     "pep-cmp-01-sub",
    #     "pep-dr-cgf-mdip-01-sub",
    #     "pep-nonprod-cgf-mdip-01-sub",
    #     "pep-prod-cgf-mdip-01-sub",
    #     "pep-dr-am-mdip-01-sub",
    #     "pep-dr-prod-am-01-sub",
    #     "pep-non-prod-am-01-sub",
    #     "pep-nonprod-am-mdip-01-sub",
    #     "pep-prod-am-01-sub",
    #     "pep-prod-am-mdip-01-sub",
    #     "pep-dr-apac-mdip-01-sub",
    #     "pep-dr-prod-apac-01-sub",
    #     "pep-non-prod-apac-01-sub",
    #     "pep-nonprod-apac-mdip-01-sub",
    #     "pep-prod-apac-01-sub",
    #     "pep-prod-apac-mdip-01-sub",
    #     "pep-dr-europe-mdip-01-sub",
    #     "pep-dr-prod-europe-01-sub",
    #     "pep-non-prod-europe-01-sub",
    #     "pep-nonprod-europe-mdip-01-sub",
    #     "pep-prod-europe-01-sub",
    #     "pep-prod-europe-mdip-01-sub",
    #     "pep-dr-pbna-mdip-01-sub",
    #     "pep-dr-prod-pbna-01-sub",
    #     "pep-nonprod-pbna-mdip-01-sub",
    #     "pep-pbna-01-sub",
    #     "pep-prod-pbna-01-sub",
    #     "pep-prod-pbna-mdip-01-sub",
    #     "pep-dr-pfna-mdip-01-sub",
    #     "pep-dr-prod-pfna-01-sub",
    #     "pep-non-prod-pfna-01-sub",
    #     "pep-nonprod-pfna-mdip-01-sub",
    #     "pep-prod-pfna-01-sub",
    #     "pep-prod-pfna-mdip-01-sub",
    #     "pep-datahub-nonprod-01-sub",
    #     "pep-datahub-nonprod-02-sub",
    #     "pep-datahub-prod-01-sub",
    #     "pep-dr-datahub-prod-01-sub",
    #     "pep-dr-researchdevelopment-01-sub",
    #     "pep-dr-sap-01-sub",
    #     "pep-researchdevelopment-01-sub",
    #     "pep-sap-01-sub",
    #     "pep-sap-nonprod-01-sub",
    #     "pep-dr-prod-01-sub",
    #     "pep-dr-prod-02-sub",
    #     "pep-nonprod-01-sub",
    #     "pep-nonprod-02-sub",
    #     "pep-prod-01-sub",
    #     "pep-prod-02-sub",
    #     "pep-storage-minp-01-sub",
    #     "pep-dr-infosectools-01-sub",
    #     "pep-infosectools-01-sub",
    #     "pep-dr-identity-01-sub",
    #     "pep-identity-01-sub",
    #     "pep-dr-sharedservice-01-sub",
    #     "pep-sharedservice-01-sub",
    #     "pep-management-01-sub",
    #     "pep-dr-prod-infratools-01-sub",
    #     "pep-nonprod-infratools-01-sub",
    #     "pep-prod-infratools-01-sub",
    #     "pep-testing-01-sub",
    #     "pep-dr-testing-01-sub",
    #     "pep-sandbox-01-sub"
    # ]

        
        subscription_names = [name.strip().strip("'") for name in os.environ.get('SUBSCRIPTION_NAMES', '').split(';')]
        valid_subs, invalid_subs = subscriptions_validations.check_valid_subscription_names(subscription_names)
        if invalid_subs:
              logger.error(f"invalid input subscriptions {invalid_subs}")
        print(subscription_names)

        # Get subscriptions
        subscriptions = [s for s in subscription_client.subscriptions.list() if s.display_name in subscription_names]

        # Use concurrent execution for fetching resources' diagnostic settings
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = []
            for subscription in subscriptions:
                id_sub = subscription.subscription_id
                res_client = ResourceManagementClient(credential, id_sub)
                monitor_client = MonitorManagementClient(credential, id_sub)
                for service, resource_type in resource_types.items():
                    print(subscription.display_name)
                    resources = res_client.resources.list(filter=f"resourceType eq '{resource_type}'")
                    for resource in resources:
                        futures.append(executor.submit(fetch_resource_diagnostic_settings,subscription.display_name, id_sub, service, resource, monitor_client))

            data = []
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    data.append(result)

        # Convert data to DataFrame
        df = pd.DataFrame(data)
        table_name = 'Azure_Resources_Diagnostic_Settings_SUB'
        container_name = 'azure-resources-diagnostic-settings-sub'
        columns = ['SubscriptionName','SubscriptionID', 'Service_Type', 'Resource_Name', 'Resource_Location', 'Diagnostic_Name', 'Logs', 'Metric_Status', 'EventHub', 'Timestamp']
        
        if not df.empty:
            # Perform further processing or actions with the DataFrame
             Azure_SQL_Convertion.SQL_function(df, table_name, columns)
             Azure_Blob_Convertion.Blob_function(df, container_name, 'main_name')
             notifications_email.send_email(container_name, container_name +' Data Report', "excel", container_name, df)

       
    except Exception as e:
        logger.error(f"An error occurred: {e}")
    finally:
        all_logs = csv_error_handler.get_all_logs()
        error_logs = csv_error_handler.get_error_logs()
        
        if all_logs:
            all_logs_df = pd.DataFrame(all_logs)
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-resources-diagnostic-settings-sub', 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-resources-diagnostic-settings-sub', 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('Exception log file generated', 'azure-resources-diagnostic-settings-sub' +' Exception Report', "excel", 'azure-resources-diagnostic-settings-sub', error_logs_df)

