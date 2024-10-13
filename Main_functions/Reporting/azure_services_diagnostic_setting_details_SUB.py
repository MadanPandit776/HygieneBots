from azure.identity import DefaultAzureCredential
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.monitor.models import DiagnosticSettingsResource, MetricSettings, LogSettings
from azure.core.exceptions import HttpResponseError
from azure.core.exceptions import ResourceNotFoundError
import sys
sys.path.append('.')
import logging
from datetime import datetime, timedelta
from Main_functions.Reporting import Azure_Resources_Diagnostic_Settings_SUB
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

def enable_diagnostic_settings():
# Initialize clients
 #credential = DefaultAzureCredential()
 credential = DefaultAzureCredential(exclude_managed_identity_credential=True)
 subscription_client = SubscriptionClient(credential)

 #subscription_names = ["XXXXXXXXXXXXXX"]

 #event_hub_details = {
 #     "eastus": {
 #         "Name_Space": "pep-itom-shared-eus-01-ehns",
 #         "Auth_ID": "/subscriptions/92ddb5ec-2ad5-45f6-b81f-e358d4904d04/resourceGroups/pep-itom-shared-eus-01-rg/providers/Microsoft.EventHub/namespaces/pep-itom-shared-eus-01-ehns/authorizationRules/RootManageSharedAccessKey",
 #         "Eventhub_Name_1": "pep-itom-shared-eus-01-eh"
 #     },
 #     "southcentralus": {
 #         "Name_Space": "pep-itom-shared-scus-01-ehns",
 #         "Auth_ID": "/subscriptions/92ddb5ec-2ad5-45f6-b81f-e358d4904d04/resourceGroups/pep-itom-shared-scus-01-rg/providers/Microsoft.EventHub/namespaces/pep-itom-shared-scus-01-ehns/authorizationRules/RootManageSharedAccessKey",
 #         "Eventhub_Name_1": "pep-itom-shared-scus-01-eh"
 #     },
 #      "uksouth": {
 #         "Name_Space": "pep-itom-shared-suk-01-ehns",
 #         "Auth_ID": "/subscriptions/92ddb5ec-2ad5-45f6-b81f-e358d4904d04/resourceGroups/pep-itom-shared-suk-01-rg/providers/Microsoft.EventHub/namespaces/pep-itom-shared-suk-01-ehns/authorizationRules/RootManageSharedAccessKey",
 #         "Eventhub_Name_1": "pep-itom-shared-suk-01-eh"
 #     },
 #     "germanywestcentral": {
 #         "Name_Space": "pep-itom-shared-gwc-01-ehns",
 #         "Auth_ID": "/subscriptions/92ddb5ec-2ad5-45f6-b81f-e358d4904d04/resourceGroups/pep-itom-shared-gwc-01-rg/providers/Microsoft.EventHub/namespaces/pep-itom-shared-gwc-01-ehns/authorizationRules/RootManageSharedAccessKey",
 #         "Eventhub_Name_1": "pep-itom-shared-gwc-01-eh"
 #     },
 #       "southeastasia": {
 #         "Name_Space": "pep-itom-shared-sea-01-ehns",
 #         "Auth_ID": "/subscriptions/92ddb5ec-2ad5-45f6-b81f-e358d4904d04/resourceGroups/pep-itom-shared-sea-01-rg/providers/Microsoft.EventHub/namespaces/pep-itom-shared-sea-01-ehns/authorizationRules/RootManageSharedAccessKey",
 #         "Eventhub_Name_1": "pep-itom-shared-sea-01-eh"
 #     },
 #      "australiaeast": {
 #         "Name_Space": "pep-itom-shared-ae-01-ehns",
 #         "Auth_ID": "/subscriptions/92ddb5ec-2ad5-45f6-b81f-e358d4904d04/resourceGroups/pep-itom-shared-ae-01-rg/providers/Microsoft.EventHub/namespaces/pep-itom-shared-ae-01-ehns/authorizationRules/RootManageSharedAccessKey",
 #         "Eventhub_Name_1": "pep-itom-shared-ae-01-eh"
 #     }  
 # }


 # Define the Event Hub namespace details for different locations
 event_hub_details = {
   "eastus": {
        "Name_Space": "TestPepD",
        "Auth_ID": "/subscriptions/XXXXXXXXXXXXXXXXXXXXX/resourceGroups/XXXXXXXXXXXXXX/providers/Microsoft.EventHub/namespaces/TestPepD/authorizationrules/RootManageSharedAccessKey",
        "Eventhub_Name_1": "testpepcp"
    },
    "westus": {
        "Name_Space": "TestEVNP",
        "Auth_ID": "/subscriptions/XXXXXXXXXXXXXXXXXXXXXXXXX/resourceGroups/XXXXXXXXXXXXXXXXX/providers/Microsoft.EventHub/namespaces/TestEVNP/authorizationrules/RootManageSharedAccessKey",
        "Eventhub_Name_1": "demoevnt"
    }
 }
 subscription_names = [name.strip().strip("'") for name in os.environ.get('SUBSCRIPTION_NAMES', '').split(';')]
 print(subscription_names)
 valid_subs, invalid_subs = subscriptions_validations.check_valid_subscription_names(subscription_names)
 if invalid_subs:
    logger.error(f"invalid input subscriptions {invalid_subs}")
# Iterate through subscriptions and enable diagnostic settings
 subscriptions = [s for s in subscription_client.subscriptions.list() if s.display_name in subscription_names]

 for subscription in subscriptions:
    subscription_id = subscription.subscription_id
    monitor_client = MonitorManagementClient(credential, subscription_id)
    resource_client = ResourceManagementClient(credential, subscription_id)

    # Get all resource groups
    resource_groups = resource_client.resource_groups.list()

    # Iterate through resource groups
    for resource_group in resource_groups:
        resource_group_name = resource_group.name

        # Fetch resources in the resource group
        resources = resource_client.resources.list_by_resource_group(resource_group_name)

        # Iterate through resources
        for resource in resources:
            resource_name = resource.name
            resource_type = resource.type
            resource_location = resource.location

            if resource_type == "Microsoft.Network/loadBalancers":
                # Check if load balancer location is in the event_hub_details dictionary
                if resource_location in event_hub_details:
                    event_hub_namespace_details = event_hub_details[resource_location]

                    # Define the resource ID
                    resource_id = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/{resource_type}/{resource_name}"
                    try:
                     existing_settings = monitor_client.diagnostic_settings.get(resource_uri=resource_id, name="diagSetByAzPolicyEventHub")
                     #logger.info(f"Diagnostic settings for {resource_type} '{resource_name}' already exist in subscription '{subscription_id}'. Skipping creation.")
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

                        logger.info(f"Diagnostic settings enabled for {resource_type} '{resource_name}' in subscription '{subscription_id}' with Event Hub details for {resource_location}.")
                     except HttpResponseError as ex:
                        if ex.status_code == 409:  # Conflict error code
                            logger.error(f"Diagnostic settings for {resource_type} '{resource_name}' in subscription '{subscription_id}' already exist. Ignoring conflict.")
                        else:
                           print(ex) 

                else:
                    logger.error(f"No Event Hub details found for the location of {resource_type} '{resource_name}' in subscription '{subscription_id}'.")

            elif resource_type == "Microsoft.Network/applicationGateways":
                # Check if application gateway location is in the event_hub_details dictionary
                if resource_location in event_hub_details:
                    event_hub_namespace_details = event_hub_details[resource_location]
                    resource_id = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/{resource_type}/{resource_name}"
                    try:
                     existing_settings = monitor_client.diagnostic_settings.get(resource_uri=resource_id, name="diagSetByAzPolicyEventHub")
                     logger.info(f"Diagnostic settings for {resource_type} '{resource_name}' already exist in subscription '{subscription_id}'. Skipping creation.")
                    except ResourceNotFoundError: 
                    # Define the diagnostic settings
                     settings_name = "diagSetByAzPolicyEventHub"
                     settings = DiagnosticSettingsResource(
                         logs=[
                     LogSettings(enabled=True, category="ApplicationGatewayAccessLog"),
                     LogSettings(enabled=True, category="ApplicationGatewayPerformanceLog"),
                     LogSettings(enabled=True, category="ApplicationGatewayFirewallLog")
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

                        logger.info(f"Diagnostic settings enabled for {resource_type} '{resource_name}' in subscription '{subscription_id}' with Event Hub details for {resource_location}.")
                     except HttpResponseError as ex:
                        if ex.status_code == 409:  # Conflict error code
                            logger.error(f"Diagnostic settings for {resource_type} '{resource_name}' in subscription '{subscription_id}' already exist. Ignoring conflict.")
                        else:
                            print(ex) 

                else:
                    logger.error(f"No Event Hub details found for the location of {resource_type} '{resource_name}' in subscription '{subscription_id}'.")

            
            elif resource_type == "Microsoft.Sql/servers/databases":
                # Check if application gateway location is in the event_hub_details dictionary
                if resource_location in event_hub_details:
                    event_hub_namespace_details = event_hub_details[resource_location]
                    resource_name_parts = resource_name.split("/")
                    database_name = resource_name_parts[-1]
                    server_name = resource_name_parts[-2]
                    resource_id = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.Sql/servers/{server_name}/databases/{database_name}"
                    try:
                     existing_settings = monitor_client.diagnostic_settings.get(resource_uri=resource_id, name="diagSetByAzPolicyEventHub")
                     logger.info(f"Diagnostic settings for {resource_type} '{resource_name}' already exist in subscription '{subscription_id}'. Skipping creation.")
                    except ResourceNotFoundError:
                     settings_name = "diagSetByAzPolicyEventHub"
                     settings = DiagnosticSettingsResource(
                          logs=[
                     LogSettings(enabled=True, category="SQLInsights"),
                     LogSettings(enabled=True, category="AutomaticTuning"),
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

                        logger.info(f"Diagnostic settings enabled for {resource_type} '{resource_name}' in subscription '{subscription_id}' with Event Hub details for {resource_location}.")
                     except HttpResponseError as ex:
                        if ex.status_code == 409:  # Conflict error code
                            logger.error(f"Diagnostic settings for {resource_type} '{resource_name}' in subscription '{subscription_id}' already exist. Ignoring conflict.")
                        else:
                            print(ex) 

                else:
                    logger.error(f"No Event Hub details found for the location of {resource_type} '{resource_name}' in subscription '{subscription_id}'.")
            elif resource_type == "Microsoft.DBforMySQL/flexibleServers":
                # Check if application gateway location is in the event_hub_details dictionary
                if resource_location in event_hub_details:
                    event_hub_namespace_details = event_hub_details[resource_location]
                    resource_id = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/{resource_type}/{resource_name}"
                    try:
                     existing_settings = monitor_client.diagnostic_settings.get(resource_uri=resource_id, name="diagSetByAzPolicyEventHub")
                     logger.info(f"Diagnostic settings for {resource_type} '{resource_name}' already exist in subscription '{subscription_id}'. Skipping creation.")
                    except ResourceNotFoundError:
                    # Define the diagnostic settings
                     settings_name = "diagSetByAzPolicyEventHub"
                    
                     settings = DiagnosticSettingsResource(
                         logs=[
                     LogSettings(enabled=True, category="MySqlSlowLogs"),
                     LogSettings(enabled=True, category="MySqlAuditLogs")
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

                        logger.info(f"Diagnostic settings enabled for {resource_type} '{resource_name}' in subscription '{subscription_id}' with Event Hub details for {resource_location}.")
                     except HttpResponseError as ex:
                        if ex.status_code == 409:  # Conflict error code
                            logger.error(f"Diagnostic settings for {resource_type} '{resource_name}' in subscription '{subscription_id}' already exist. Ignoring conflict.")
                        else:
                            print(ex) 

                else:
                     logger.error(f"No Event Hub details found for the location of {resource_type} '{resource_name}' in subscription '{subscription_id}'.")
            elif resource_type == "Microsoft.DBforMySQL/servers":
                # Check if application gateway location is in the event_hub_details dictionary
                if resource_location in event_hub_details:
                    event_hub_namespace_details = event_hub_details[resource_location]
                    resource_id = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/{resource_type}/{resource_name}"
                    try:
                     existing_settings = monitor_client.diagnostic_settings.get(resource_uri=resource_id, name="diagSetByAzPolicyEventHub")
                     logger.info(f"Diagnostic settings for {resource_type} '{resource_name}' already exist in subscription '{subscription_id}'. Skipping creation.")
                    except ResourceNotFoundError:
                    # Define the diagnostic settings
                     settings_name = "diagSetByAzPolicyEventHub"
                    
                     settings = DiagnosticSettingsResource(
                         logs=[
                     LogSettings(enabled=True, category="MySqlSlowLogs"),
                     LogSettings(enabled=True, category="MySqlAuditLogs")
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

                        logger.info(f"Diagnostic settings enabled for {resource_type} '{resource_name}' in subscription '{subscription_id}' with Event Hub details for {resource_location}.")
                     except HttpResponseError as ex:
                        if ex.status_code == 409:  # Conflict error code
                             logger.error(f"Diagnostic settings for {resource_type} '{resource_name}' in subscription '{subscription_id}' already exist. Ignoring conflict.")
                        else:
                            print(ex) 

                else:
                     logger.error(f"No Event Hub details found for the location of {resource_type} '{resource_name}' in subscription '{subscription_id}'.")
            elif resource_type == "Microsoft.ContainerService/managedClusters":
                # Check if AKS  location is in the event_hub_details dictionary
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

                        logger.info(f"Diagnostic settings enabled for {resource_type} '{resource_name}' in subscription '{subscription_id}' with Event Hub details for {resource_location}.")
                     except HttpResponseError as ex:
                        if ex.status_code == 409:  # Conflict error code
                             logger.error(f"Diagnostic settings for {resource_type} '{resource_name}' in subscription '{subscription_id}' already exist. Ignoring conflict.")
                        else:
                            print(ex) 

                else:
                     logging.error(f"No Event Hub details found for the location of {resource_type} '{resource_name}' in subscription '{subscription_id}'.")
            elif resource_type == "Microsoft.Cdn/profiles":
                # Check if Front door location is in the event_hub_details dictionary
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
                     LogSettings(enabled=True, category="FrontDoorAccessLog"),
                     LogSettings(enabled=True, category="FrontDoorHealthProbeLog"),
                     LogSettings(enabled=True, category="FrontDoorWebApplicationFirewallLog")
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

                        logging.info(f"Diagnostic settings enabled for {resource_type} '{resource_name}' in subscription '{subscription_id}' with Event Hub details for {resource_location}.")
                     except HttpResponseError as ex:
                        if ex.status_code == 409:  # Conflict error code
                             logger.error(f"Diagnostic settings for {resource_type} '{resource_name}' in subscription '{subscription_id}' already exist. Ignoring conflict.")
                        else:
                            print(ex) 

                else:
                     logger.error(f"No Event Hub details found for the location of {resource_type} '{resource_name}' in subscription '{subscription_id}'.")
            elif resource_type == "Microsoft.Cache/Redis":
                # Check if  Azure Redis location is in the event_hub_details dictionary
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
                     LogSettings(enabled=True, category="ConnectedClientList")
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

                        logger.info(f"Diagnostic settings enabled for {resource_type} '{resource_name}' in subscription '{subscription_id}' with Event Hub details for {resource_location}.")
                     except HttpResponseError as ex:
                        if ex.status_code == 409:  # Conflict error code
                             logger.error(f"Diagnostic settings for {resource_type} '{resource_name}' in subscription '{subscription_id}' already exist. Ignoring conflict.")
                        else:
                            print(ex)

                else:
                     logger.error(f"No Event Hub details found for the location of {resource_type} '{resource_name}' in subscription '{subscription_id}'.")

#enable_diagnostic_settings()
Azure_Resources_Diagnostic_Settings_SUB.get_report_dig_settings_sub()
