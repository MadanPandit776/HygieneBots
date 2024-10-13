from azure.identity import DefaultAzureCredential
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.monitor.models import DiagnosticSettingsResource, MetricSettings,LogSettings
from azure.core.exceptions import HttpResponseError
import sys
sys.path.append('.')
import logging
from datetime import datetime, timedelta
from azure.core.exceptions import ResourceNotFoundError
from Main_functions.Reporting import Azure_Resources_Diagnostic_Settings_RG
from Main_functions.Reporting import Azure_Resources_Diagnostic_Settings_Data_Explorer
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

def enable_diagnostic_settings():
# Initialize clients
 credential = DefaultAzureCredential(exclude_managed_identity_credential=True)
 #credential = DefaultAzureCredential()

# Define the Event Hub namespace details for different locations

 event_hub_details = {
     "eastus": {
         "Name_Space": "pep-itom-shared-eus-01-ehns",
         "Auth_ID": "/subscriptions/92ddb5ec-2ad5-45f6-b81f-e358d4904d04/resourceGroups/pep-itom-shared-eus-01-rg/providers/Microsoft.EventHub/namespaces/pep-itom-shared-eus-01-ehns/authorizationRules/RootManageSharedAccessKey",
         "Eventhub_Name_1": "pep-itom-pepsense-eus-01-eh"
     },
     "southcentralus": {
         "Name_Space": "pep-itom-shared-scus-01-ehns",
         "Auth_ID": "/subscriptions/92ddb5ec-2ad5-45f6-b81f-e358d4904d04/resourceGroups/pep-itom-shared-scus-01-rg/providers/Microsoft.EventHub/namespaces/pep-itom-shared-scus-01-ehns/authorizationRules/RootManageSharedAccessKey",
         "Eventhub_Name_1": "pep-itom-pepsense-scus-01-eh"
     },
      "uksouth": {
         "Name_Space": "pep-itom-shared-suk-01-ehns",
         "Auth_ID": "/subscriptions/92ddb5ec-2ad5-45f6-b81f-e358d4904d04/resourceGroups/pep-itom-shared-suk-01-rg/providers/Microsoft.EventHub/namespaces/pep-itom-shared-suk-01-ehns/authorizationRules/RootManageSharedAccessKey",
         "Eventhub_Name_1": "pep-itom-shared-suk-01-eh"
     },
     "germanywestcentral": {
         "Name_Space": "pep-itom-shared-gwc-01-ehns",
         "Auth_ID": "/subscriptions/92ddb5ec-2ad5-45f6-b81f-e358d4904d04/resourceGroups/pep-itom-shared-gwc-01-rg/providers/Microsoft.EventHub/namespaces/pep-itom-shared-gwc-01-ehns/authorizationRules/RootManageSharedAccessKey",
         "Eventhub_Name_1": "pep-itom-shared-gwc-01-eh"
     },
       "southeastasia": {
         "Name_Space": "pep-itom-shared-sea-01-ehns",
         "Auth_ID": "/subscriptions/92ddb5ec-2ad5-45f6-b81f-e358d4904d04/resourceGroups/pep-itom-shared-sea-01-rg/providers/Microsoft.EventHub/namespaces/pep-itom-shared-sea-01-ehns/authorizationRules/RootManageSharedAccessKey",
         "Eventhub_Name_1": "pep-itom-shared-sea-01-eh"
     },
      "australiaeast": {
         "Name_Space": "pep-itom-shared-ae-01-ehns",
         "Auth_ID": "/subscriptions/92ddb5ec-2ad5-45f6-b81f-e358d4904d04/resourceGroups/pep-itom-shared-ae-01-rg/providers/Microsoft.EventHub/namespaces/pep-itom-shared-ae-01-ehns/authorizationRules/RootManageSharedAccessKey",
         "Eventhub_Name_1": "pep-itom-shared-ae-01-eh"
     }
    
 }
 

 # Iterate through subscriptions and resource groups
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
    # Initialize clients for the specified subscription
    monitor_client = MonitorManagementClient(credential, subscription_id)
    resource_client = ResourceManagementClient(credential, subscription_id)

    for resource_group_name in resource_groups:
        print(resource_group_name)
        # Fetch resources in the specified resource group
        resources = resource_client.resources.list_by_resource_group(resource_group_name)

        # Iterate through resources
        for resource in resources:
          resource_name = resource.name
          resource_type = resource.type
          resource_location = resource.location
          if resource_type == "Microsoft.EventHub/namespaces" :
               # Check if load balancer location is in the event_hub_details dictionary
            if resource_location in event_hub_details:
                    event_hub_namespace_details = event_hub_details[resource_location]
                    resource_id = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/{resource_type}/{resource_name}"
                    try:
                     existing_settings = monitor_client.diagnostic_settings.get(resource_uri=resource_id, name="diagSetByAzPolicyEventHub")
                     logger.info(f"Diagnostic settings for {resource_type} '{resource_name}' already exist in subscription '{subscription_id}'. Skipping creation.")
                    except ResourceNotFoundError:

                    # Define the resource ID
                     # Exclude specific Event Hubs
                     excluded_event_hubs = ["pep-itom-shared-eus-01-ehns","pep-itom-shared-scus-01-ehns","pep-itom-shared-suk-01-ehns","pep-itom-shared-gwc-01-ehns","pep-itom-shared-sea-01-ehns","pep-itom-shared-ae-01-ehns"]

                     if resource_name not in excluded_event_hubs:
                    # Define the diagnostic settings
                      settings_name = "diagSetByAzPolicyEventHub"

                      settings = DiagnosticSettingsResource(
                         logs=[
                     LogSettings(enabled=True, category="DiagnosticErrorLogs"),
                     LogSettings(enabled=True, category="ArchiveLogs"),
                     LogSettings(enabled=True, category="OperationalLogs"),
                     LogSettings(enabled=True, category="AutoScaleLogs"),
                     LogSettings(enabled=True, category="KafkaCoordinatorLogs"),
                     LogSettings(enabled=True, category="KafkaUserErrorLogs"),
                     LogSettings(enabled=True, category="EventHubVNetConnectionEvent"),
                     LogSettings(enabled=True, category="CustomerManagedKeyUserLogs"),
                     LogSettings(enabled=True, category="RuntimeAuditLogs"),
                     LogSettings(enabled=True, category="ApplicationMetricsLogs")
                     ],
                        metrics=[MetricSettings(enabled=True, category="AllMetrics")],
                        event_hub_authorization_rule_id=event_hub_namespace_details["Auth_ID"],
                        event_hub_name=event_hub_namespace_details["Eventhub_Name_1"]
                      )

                      try:
                        # Enable diagnostic settings
                        monitor_client.diagnostic_settings.create_or_update(
                            resource_uri=resource_id,
                            name=settings_name,
                            parameters=settings
                        )

                        logger.info(f"Diagnostic settings enabled for {resource_type} '{resource_name}' in subscription '{subscription_id}' with Event Hub details for {resource_location} and resource group '{resource_group_name}'.")
                      except HttpResponseError as ex:
                        if ex.status_code == 409:  # Conflict error code
                            logger.error(f"Diagnostic settings for {resource_type} '{resource_name}' in subscription '{subscription_id}' already exist in resource group '{resource_group_name}'. Ignoring conflict.")
                        else:
                            print(ex) 
                     else:
                      logger.error(f"Skipping enabling diagnostic settings for Event Hub '{resource_name}' in subscription '{subscription_id}' and resource group '{resource_group_name}'.")

            else:
                    logger.error(f"No Event Hub details found for the location of {resource_type} '{resource_name}' in subscription '{subscription_id}' and resource group '{resource_group_name}'.")
               
          if resource_type == "Microsoft.Web/serverFarms":
                # Check if load balancer location is in the event_hub_details dictionary
                if resource_location in event_hub_details:
                    event_hub_namespace_details = event_hub_details[resource_location]

                    # Define the resource ID
                    resource_id = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/{resource_type}/{resource_name}"
                    try:
                     existing_settings = monitor_client.diagnostic_settings.get(resource_uri=resource_id, name="diagSetByAzPolicyEventHub")
                     logger.info(f"Diagnostic settings for {resource_type} '{resource_name}' already exist in subscription '{subscription_id}'. Skipping creation.")
                    except ResourceNotFoundError:
                    # Define the diagnostic settings
                     settings_name = "diagSetByAzPolicyEventHub"

                     settings = DiagnosticSettingsResource(
                        metrics=[MetricSettings(enabled=True, category="AllMetrics")],
                        event_hub_authorization_rule_id=event_hub_namespace_details["Auth_ID"],
                        event_hub_name=event_hub_namespace_details["Eventhub_Name_1"]
                     )

                     try:
                        # Enable diagnostic settings
                        monitor_client.diagnostic_settings.create_or_update(
                            resource_uri=resource_id,
                            name=settings_name,
                            parameters=settings
                        )

                        logger.info(f"Diagnostic settings enabled for {resource_type} '{resource_name}' in subscription '{subscription_id}' with Event Hub details for {resource_location} and resource group '{resource_group_name}'.")
                     except HttpResponseError as ex:
                        if ex.status_code == 409:  # Conflict error code
                            logger.error(f"Diagnostic settings for {resource_type} '{resource_name}' in subscription '{subscription_id}' already exist in resource group '{resource_group_name}'. Ignoring conflict.")
                        else:
                           print(ex) 

                else:
                    logger.error(f"No Event Hub details found for the location of {resource_type} '{resource_name}' in subscription '{subscription_id}' and resource group '{resource_group_name}'.")
          
          elif resource_type == "Microsoft.Web/hostingEnvironments":
                # Check if AppService ENV location is in the event_hub_details dictionary
                if resource_location in event_hub_details:
                    event_hub_namespace_details = event_hub_details[resource_location]

                    # Define the resource ID
                    resource_id = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/{resource_type}/{resource_name}"
                    try:
                     existing_settings = monitor_client.diagnostic_settings.get(resource_uri=resource_id, name="diagSetByAzPolicyEventHub")
                     logger.info(f"Diagnostic settings for {resource_type} '{resource_name}' already exist in subscription '{subscription_id}'. Skipping creation.")
                    except ResourceNotFoundError:
                    # Define the diagnostic settings
                     settings_name = "diagSetByAzPolicyEventHub"

                     settings = DiagnosticSettingsResource(
                         logs=[
                     LogSettings(enabled=True, category="AppServiceEnvironmentPlatformLogs")
                     ],
                        event_hub_authorization_rule_id=event_hub_namespace_details["Auth_ID"],
                        event_hub_name=event_hub_namespace_details["Eventhub_Name_1"]
                     )

                     try:
                        # Enable diagnostic settings
                        monitor_client.diagnostic_settings.create_or_update(
                            resource_uri=resource_id,
                            name=settings_name,
                            parameters=settings
                        )

                        logger.info(f"Diagnostic settings enabled for {resource_type} '{resource_name}' in subscription '{subscription_id}' with Event Hub details for {resource_location} and resource group '{resource_group_name}'.")
                     except HttpResponseError as ex:
                        if ex.status_code == 409:  # Conflict error code
                            logger.error(f"Diagnostic settings for {resource_type} '{resource_name}' in subscription '{subscription_id}' already exist in resource group '{resource_group_name}'. Ignoring conflict.")
                        else:
                           print(ex) 

                else:
                    logger.error(f"No Event Hub details found for the location of {resource_type} '{resource_name}' in subscription '{subscription_id}' and resource group '{resource_group_name}'.")
          elif resource_type == "Microsoft.KeyVault/vaults":
                # Check if load balancer location is in the event_hub_details dictionary
                if resource_location in event_hub_details:
                    event_hub_namespace_details = event_hub_details[resource_location]

                    # Define the resource ID
                    resource_id = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/{resource_type}/{resource_name}"
                    try:
                     existing_settings = monitor_client.diagnostic_settings.get(resource_uri=resource_id, name="diagSetByAzPolicyEventHub")
                     logger.info(f"Diagnostic settings for {resource_type} '{resource_name}' already exist in subscription '{subscription_id}'. Skipping creation.")
                    except ResourceNotFoundError:
                    # Define the diagnostic settings
                     settings_name = "diagSetByAzPolicyEventHub"

                     settings = DiagnosticSettingsResource(
                         logs=[
                     LogSettings(enabled=True, category="AuditEvent"),
                     LogSettings(enabled=True, category="AzurePolicyEvaluationDetails")
                     ],
                        metrics=[MetricSettings(enabled=True, category="AllMetrics")],
                        event_hub_authorization_rule_id=event_hub_namespace_details["Auth_ID"],
                        event_hub_name=event_hub_namespace_details["Eventhub_Name_1"]
                     )

                     try:
                        # Enable diagnostic settings
                        monitor_client.diagnostic_settings.create_or_update(
                            resource_uri=resource_id,
                            name=settings_name,
                            parameters=settings
                        )

                        logger.info(f"Diagnostic settings enabled for {resource_type} '{resource_name}' in subscription '{subscription_id}' with Event Hub details for {resource_location} and resource group '{resource_group_name}'.")
                     except HttpResponseError as ex:
                        if ex.status_code == 409:  # Conflict error code
                            logger.error(f"Diagnostic settings for {resource_type} '{resource_name}' in subscription '{subscription_id}' already exist in resource group '{resource_group_name}'. Ignoring conflict.")
                        else:
                            print(ex) 

                else:
                    logger.error(f"No Event Hub details found for the location of {resource_type} '{resource_name}' in subscription '{subscription_id}' and resource group '{resource_group_name}'.")
          elif resource_type == "Microsoft.ServiceBus/namespaces":
                # Check if load balancer location is in the event_hub_details dictionary
                if resource_location in event_hub_details:
                    event_hub_namespace_details = event_hub_details[resource_location]

                    # Define the resource ID
                    resource_id = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/{resource_type}/{resource_name}"
                    try:
                     existing_settings = monitor_client.diagnostic_settings.get(resource_uri=resource_id, name="diagSetByAzPolicyEventHub")
                     logger.info(f"Diagnostic settings for {resource_type} '{resource_name}' already exist in subscription '{subscription_id}'. Skipping creation.")
                    except ResourceNotFoundError:
                    # Define the diagnostic settings
                     settings_name = "diagSetByAzPolicyEventHub"

                     settings = DiagnosticSettingsResource(
                         logs=[
                     LogSettings(enabled=True, category="DiagnosticErrorLogs"),
                     LogSettings(enabled=True, category="OperationalLogs"),
                     LogSettings(enabled=True, category="VNetAndIPFilteringLogs"),
                     LogSettings(enabled=True, category="RuntimeAuditLogs"),
                     LogSettings(enabled=True, category="ApplicationMetricsLogs"),
                         ],
                        metrics=[MetricSettings(enabled=True, category="AllMetrics")],
                        event_hub_authorization_rule_id=event_hub_namespace_details["Auth_ID"],
                        event_hub_name=event_hub_namespace_details["Eventhub_Name_1"]
                     )

                     try:
                        # Enable diagnostic settings
                        monitor_client.diagnostic_settings.create_or_update(
                            resource_uri=resource_id,
                            name=settings_name,
                            parameters=settings
                        )

                        logger.info(f"Diagnostic settings enabled for {resource_type} '{resource_name}' in subscription '{subscription_id}' with Event Hub details for {resource_location} and resource group '{resource_group_name}'.")
                     except HttpResponseError as ex:
                        if ex.status_code == 409:  # Conflict error code
                            logger.error(f"Diagnostic settings for {resource_type} '{resource_name}' in subscription '{subscription_id}' already exist in resource group '{resource_group_name}'. Ignoring conflict.")
                        else:
                            print(ex) 

                else:
                    logger.error(f"No Event Hub details found for the location of {resource_type} '{resource_name}' in subscription '{subscription_id}' and resource group '{resource_group_name}'.")
          elif resource_type == "Microsoft.DocumentDb/databaseAccounts":
                # Check if load balancer location is in the event_hub_details dictionary
                if resource_location in event_hub_details:
                    event_hub_namespace_details = event_hub_details[resource_location]

                    # Define the resource ID
                    resource_id = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/{resource_type}/{resource_name}"
                    try:
                     existing_settings = monitor_client.diagnostic_settings.get(resource_uri=resource_id, name="diagSetByAzPolicyEventHub")
                     logger.info(f"Diagnostic settings for {resource_type} '{resource_name}' already exist in subscription '{subscription_id}'. Skipping creation.")
                    except ResourceNotFoundError:
                    # Define the diagnostic settings
                     settings_name = "diagSetByAzPolicyEventHub"

                     settings = DiagnosticSettingsResource(
                         logs=[
                     LogSettings(enabled=True, category="DataPlaneRequests"),
                     LogSettings(enabled=True, category="MongoRequests"),
                     LogSettings(enabled=True, category="QueryRuntimeStatistics"),
                     LogSettings(enabled=True, category="PartitionKeyStatistics"),
                     LogSettings(enabled=True, category="PartitionKeyRUConsumption"),
                     LogSettings(enabled=True, category="ControlPlaneRequests"),
                     LogSettings(enabled=True, category="CassandraRequests"),
                     LogSettings(enabled=True, category="GremlinRequests"),
                     LogSettings(enabled=True, category="TableApiRequests")
                         ],
                        metrics=[MetricSettings(enabled=True, category="AllMetrics")],
                        event_hub_authorization_rule_id=event_hub_namespace_details["Auth_ID"],
                        event_hub_name=event_hub_namespace_details["Eventhub_Name_1"]
                     )

                     try:
                        # Enable diagnostic settings
                        monitor_client.diagnostic_settings.create_or_update(
                            resource_uri=resource_id,
                            name=settings_name,
                            parameters=settings
                        )

                        logger.info(f"Diagnostic settings enabled for {resource_type} '{resource_name}' in subscription '{subscription_id}' with Event Hub details for {resource_location} and resource group '{resource_group_name}'.")
                     except HttpResponseError as ex:
                        if ex.status_code == 409:  # Conflict error code
                            logger.error(f"Diagnostic settings for {resource_type} '{resource_name}' in subscription '{subscription_id}' already exist in resource group '{resource_group_name}'. Ignoring conflict.")
                        else:
                            print(ex) 

                else:
                    logger.error(f"No Event Hub details found for the location of {resource_type} '{resource_name}' in subscription '{subscription_id}' and resource group '{resource_group_name}'.")
          elif resource_type == "Microsoft.Kusto/clusters":
                #DataExplorer Cluster 
                # Check if load balancer location is in the event_hub_details dictionary
                if resource_location in event_hub_details:
                    event_hub_namespace_details = event_hub_details[resource_location]
     
                    # Define the resource ID
                    resource_id = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/{resource_type}/{resource_name}"
                    try:
                     existing_settings = monitor_client.diagnostic_settings.get(resource_uri=resource_id, name="diagSetByAzPolicyEventHub")
                     logger.info(f"Diagnostic settings for {resource_type} '{resource_name}' already exist in subscription '{subscription_id}'. Skipping creation.")
                    except ResourceNotFoundError:
                    # Define the diagnostic settings
                     settings_name = "diagSetByAzPolicyEventHub"

                     settings = DiagnosticSettingsResource(
                         logs=[
                     LogSettings(enabled=True, category="SucceededIngestion"),
                     LogSettings(enabled=True, category="FailedIngestion"),
                     LogSettings(enabled=True, category="IngestionBatching"),
                     LogSettings(enabled=True, category="Command"),
                     LogSettings(enabled=True, category="Query"),
                     LogSettings(enabled=True, category="TableUsageStatistics"),
                     LogSettings(enabled=True, category="TableDetails"),
                     LogSettings(enabled=True, category="Journal")
                         ],
                        metrics=[MetricSettings(enabled=True, category="AllMetrics")],
                        event_hub_authorization_rule_id=event_hub_namespace_details["Auth_ID"],
                        event_hub_name=event_hub_namespace_details["Eventhub_Name_1"]
                     )

                     try:
                        # Enable diagnostic settings
                        monitor_client.diagnostic_settings.create_or_update(
                            resource_uri=resource_id,
                            name=settings_name,
                            parameters=settings
                        )

                        logger.info(f"Diagnostic settings enabled for {resource_type} '{resource_name}' in subscription '{subscription_id}' with Event Hub details for {resource_location} and resource group '{resource_group_name}'.")
                     except HttpResponseError as ex:
                        if ex.status_code == 409:  # Conflict error code
                            logger.error(f"Diagnostic settings for {resource_type} '{resource_name}' in subscription '{subscription_id}' already exist in resource group '{resource_group_name}'. Ignoring conflict.")
                        else:
                            print(ex) 

                else:
                    logger.error(f"No Event Hub details found for the location of {resource_type} '{resource_name}' in subscription '{subscription_id}' and resource group '{resource_group_name}'.")
          elif resource_type == "Microsoft.Devices/IotHubs":
                # Check if load balancer location is in the event_hub_details dictionary
                if resource_location in event_hub_details:
                    event_hub_namespace_details = event_hub_details[resource_location]

                    # Define the resource ID
                    resource_id = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/{resource_type}/{resource_name}"
                    try:
                     existing_settings = monitor_client.diagnostic_settings.get(resource_uri=resource_id, name="diagSetByAzPolicyEventHub")
                     logger.info(f"Diagnostic settings for {resource_type} '{resource_name}' already exist in subscription '{subscription_id}'. Skipping creation.")
                    except ResourceNotFoundError:
                    # Define the diagnostic settings
                     settings_name = "diagSetByAzPolicyEventHub"

                     settings = DiagnosticSettingsResource(
                        logs=[
                     LogSettings(enabled=True, category="DigitalTwinsOperation"),
                     LogSettings(enabled=True, category="EventRoutesOperation"),
                     LogSettings(enabled=True, category="DataHistoryOperation"),
                     LogSettings(enabled=True, category="ModelsOperation"),
                     LogSettings(enabled=True, category="QueryOperation"),
                     LogSettings(enabled=True, category="ResourceProviderOperation")
                         ],
                    
                        metrics=[MetricSettings(enabled=True, category="AllMetrics")],
                        event_hub_authorization_rule_id=event_hub_namespace_details["Auth_ID"],
                        event_hub_name=event_hub_namespace_details["Eventhub_Name_1"]
                     )

                     try:
                        # Enable diagnostic settings
                        monitor_client.diagnostic_settings.create_or_update(
                            resource_uri=resource_id,
                            name=settings_name,
                            parameters=settings
                        )

                        logger.error(f"Diagnostic settings enabled for {resource_type} '{resource_name}' in subscription '{subscription_id}' with Event Hub details for {resource_location} and resource group '{resource_group_name}'.")
                     except HttpResponseError as ex:
                        if ex.status_code == 409:  # Conflict error code
                            logger.error(f"Diagnostic settings for {resource_type} '{resource_name}' in subscription '{subscription_id}' already exist in resource group '{resource_group_name}'. Ignoring conflict.")
                        else:
                            print(ex) 

                else:
                    logger.error(f"No Event Hub details found for the location of {resource_type} '{resource_name}' in subscription '{subscription_id}' and resource group '{resource_group_name}'.")
          elif resource_type == "Microsoft.DigitalTwins/digitalTwinsInstances":
                # Check if load balancer location is in the event_hub_details dictionary
                if resource_location in event_hub_details:
                    event_hub_namespace_details = event_hub_details[resource_location]

                    # Define the resource ID
                    resource_id = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/{resource_type}/{resource_name}"
                    try:
                     existing_settings = monitor_client.diagnostic_settings.get(resource_uri=resource_id, name="diagSetByAzPolicyEventHub")
                     logger.info(f"Diagnostic settings for {resource_type} '{resource_name}' already exist in subscription '{subscription_id}'. Skipping creation.")
                    except ResourceNotFoundError:
                    # Define the diagnostic settings
                     settings_name = "diagSetByAzPolicyEventHub"

                     settings = DiagnosticSettingsResource(
                    
                        metrics=[MetricSettings(enabled=True, category="AllMetrics")],
                        event_hub_authorization_rule_id=event_hub_namespace_details["Auth_ID"],
                        event_hub_name=event_hub_namespace_details["Eventhub_Name_1"]
                     )

                     try:
                        # Enable diagnostic settings
                        monitor_client.diagnostic_settings.create_or_update(
                            resource_uri=resource_id,
                            name=settings_name,
                            parameters=settings
                        )

                        logger.info(f"Diagnostic settings enabled for {resource_type} '{resource_name}' in subscription '{subscription_id}' with Event Hub details for {resource_location} and resource group '{resource_group_name}'.")
                     except HttpResponseError as ex:
                        if ex.status_code == 409:  # Conflict error code
                            logger.error(f"Diagnostic settings for {resource_type} '{resource_name}' in subscription '{subscription_id}' already exist in resource group '{resource_group_name}'. Ignoring conflict.")
                        else:
                            print(ex) 

                else:
                    logger.error(f"No Event Hub details found for the location of {resource_type} '{resource_name}' in subscription '{subscription_id}' and resource group '{resource_group_name}'.")
          elif resource_type == "Microsoft.EventGrid/systemTopics":
                # Check if load balancer location is in the event_hub_details dictionary
                if resource_location in event_hub_details:
                    event_hub_namespace_details = event_hub_details[resource_location]

                    # Define the resource ID
                    resource_id = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/{resource_type}/{resource_name}"
                    try:
                     existing_settings = monitor_client.diagnostic_settings.get(resource_uri=resource_id, name="diagSetByAzPolicyEventHub")
                     logger.info(f"Diagnostic settings for {resource_type} '{resource_name}' already exist in subscription '{subscription_id}'. Skipping creation.")
                    except ResourceNotFoundError:
                    # Define the diagnostic settings
                     settings_name = "diagSetByAzPolicyEventHub"

                     settings = DiagnosticSettingsResource(
                        logs=[
                     LogSettings(enabled=True, category="DeliveryFailures")
                         ],
                        metrics=[MetricSettings(enabled=True, category="AllMetrics")],
                        event_hub_authorization_rule_id=event_hub_namespace_details["Auth_ID"],
                        event_hub_name=event_hub_namespace_details["Eventhub_Name_1"]
                     )

                     try:
                        # Enable diagnostic settings
                        monitor_client.diagnostic_settings.create_or_update(
                            resource_uri=resource_id,
                            name=settings_name,
                            parameters=settings
                        )

                        logger.info(f"Diagnostic settings enabled for {resource_type} '{resource_name}' in subscription '{subscription_id}' with Event Hub details for {resource_location} and resource group '{resource_group_name}'.")
                     except HttpResponseError as ex:
                        if ex.status_code == 409:  # Conflict error code
                            logger.error(f"Diagnostic settings for {resource_type} '{resource_name}' in subscription '{subscription_id}' already exist in resource group '{resource_group_name}'. Ignoring conflict.")
                        else:
                            print(ex) 

                else:
                    logger.error(f"No Event Hub details found for the location of {resource_type} '{resource_name}' in subscription '{subscription_id}' and resource group '{resource_group_name}'.")
          elif resource_type == "Microsoft.Web/sites" and (resource.kind == "functionapp,linux" or resource.kind == "functionapp"):
                if resource_location in event_hub_details:
                    event_hub_namespace_details = event_hub_details[resource_location]
                    # Define the resource ID
                    resource_id = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/{resource_type}/{resource_name}"
                    try:
                     existing_settings = monitor_client.diagnostic_settings.get(resource_uri=resource_id, name="diagSetByAzPolicyEventHub")
                     logger.info(f"Diagnostic settings for {resource_type} '{resource_name}' already exist in subscription '{subscription_id}'. Skipping creation.")
                    except ResourceNotFoundError:
                    # Define the diagnostic settings
                     settings_name = "diagSetByAzPolicyEventHub"

                     settings = DiagnosticSettingsResource(
                        logs=[
                     LogSettings(enabled=True, category="FunctionAppLogs"),
                     LogSettings(enabled=True, category="AppServiceAuthenticationLogs")
                         ],
                        metrics=[MetricSettings(enabled=True, category="AllMetrics")],
                        event_hub_authorization_rule_id=event_hub_namespace_details["Auth_ID"],
                        event_hub_name=event_hub_namespace_details["Eventhub_Name_1"]
                     )

                     try:
                        # Enable diagnostic settings
                        monitor_client.diagnostic_settings.create_or_update(
                            resource_uri=resource_id,
                            name=settings_name,
                            parameters=settings
                        )

                        logger.info(f"Diagnostic settings enabled for {resource_type} '{resource_name}' in subscription '{subscription_id}' with Event Hub details for {resource_location} and resource group '{resource_group_name}'.")
                     except HttpResponseError as ex:
                        if ex.status_code == 409:  # Conflict error code
                            logger.error(f"Diagnostic settings for {resource_type} '{resource_name}' in subscription '{subscription_id}' already exist in resource group '{resource_group_name}'. Ignoring conflict.")
                        else:
                            print(ex) 

                else:
                    logger.error(f"No Event Hub details found for the location of {resource_type} '{resource_name}' in subscription '{subscription_id}' and resource group '{resource_group_name}'.")

# Enable or Disable enable_diagnostic_settings()
#enable_diagnostic_settings()
Azure_Resources_Diagnostic_Settings_RG.generate_azure_resources_report()
Azure_Resources_Diagnostic_Settings_Data_Explorer.generate_azure_data_explorer_resources_report()
