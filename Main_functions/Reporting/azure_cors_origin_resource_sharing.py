import logging
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.web import WebSiteManagementClient
import pandas as pd
from datetime import datetime, timedelta
import sys
import os
sys.path.append('.')
from concurrent.futures import ThreadPoolExecutor, as_completed
from Class.Report_handler import Azure_SQL_Convertion
from Class.Report_handler import Azure_Blob_Convertion
from Class.Logging.csv_error_handler import CSVErrorHandler
from Class.Email import notifications_email
from Class.Logging import subscriptions_validations

# Create lists to store logs
all_logs = []
error_logs = []

# Instantiate the handler
handler = CSVErrorHandler()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)

def process_app(app, subscription_name, subscription_id, web_client):
    cors_settings = []
    resource_group_name = app.resource_group
    app_name = app.name
    app_kind = app.kind
    try:
        app_config = web_client.web_apps.get_configuration(resource_group_name, app_name)
        if app_config is not None and app_config.cors is not None and app_config.cors.allowed_origins is not None:
            cst_time = datetime.utcnow() - timedelta(hours=6)
            cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
            cors_settings.append({
                'SubscriptionName': subscription_name,
                'Subscription': subscription_id,
                'Resource_Group_Name': resource_group_name,
                'App_Name': app_name,
                'App_Type': app_kind,
                'CORS': ', '.join(app_config.cors.allowed_origins) if app_config.cors.allowed_origins else "Not configured",
                'Timestamp': cst_time_str
            })
            logger.info(f"Found cross origin for: {app_name} in subscription {subscription_name}")
    except Exception as e:
        logger.error(f'Failed to get configuration for app {app_name} in subscription {subscription_name}: {e}')
    return cors_settings

def process_subscription(subscription, credential):
    cors_settings = []
    try:
        subscription_id = subscription.subscription_id
        subscription_name = subscription.display_name  
        web_client = WebSiteManagementClient(credential, subscription_id)
        apps = list(web_client.web_apps.list())
        apps.sort(key=lambda app: (app.kind != 'functionapp', app.kind != 'apiapp'))

        # Process each app in parallel
        with ThreadPoolExecutor() as executor:
            futures = []
            for app in apps:
                futures.append(executor.submit(process_app, app, subscription_name, subscription_id, web_client))
            
            for future in as_completed(futures):
                cors_settings.extend(future.result())

    except Exception as e:
        logger.error(f'An error occurred during subscription loop: {e}')
    return cors_settings

def get_cors_settings():
    try:
        credential = DefaultAzureCredential()
        #credential = DefaultAzureCredential(exclude_managed_identity_credential=True)
        subscription_client = SubscriptionClient(credential)
        cors_settings = []

        user_input = sys.argv[1] if len(sys.argv) > 1 else "all"
        if user_input.lower() == "all":
            subscriptions = list(subscription_client.subscriptions.list())
        else:
            subscription_names = [s.strip() for s in user_input.split(",")]
            subscriptions = [s for s in subscription_client.subscriptions.list() if s.display_name in subscription_names]
            valid_subs, invalid_subs = subscriptions_validations.check_valid_subscription_names(subscription_names)
            if invalid_subs:
              logger.error(f"invalid input subscriptions {invalid_subs}")
        
        # Process each subscription in parallel
        with ThreadPoolExecutor() as executor:
            futures = []
            for subscription in subscriptions:
                futures.append(executor.submit(process_subscription, subscription, credential))
            
            for future in as_completed(futures):
                cors_settings.extend(future.result())

        # Save results to Azure SQL and Blob Storage
        if cors_settings: 
            table_name = 'azure_cross_origin_resource_sharing'
            container_name = 'azure-cross-origin-resource-sharing'
            df = pd.DataFrame(cors_settings)
            columns = ['SubscriptionName', 'Subscription', 'Resource_Group_Name', 'App_Name', 'App_Type', 'CORS', 'Timestamp']
            Azure_SQL_Convertion.SQL_function(df, table_name, columns)
            Azure_Blob_Convertion.Blob_function(df, container_name, 'main_name')
            notifications_email.send_email("Azure cross origin resource sharing", 'Bot Report : ' + container_name, "excel", container_name, df)

    except Exception as e:
        logger.error(f'An error occurred: {e}')
    finally:
        # Retrieve logs from the handler (only Azure SDK logs)
        all_logs = handler.get_all_logs()
        error_logs = handler.get_error_logs()
        # Save Azure SDK logs to Blob Storage
       
        if all_logs:
            all_logs_df = pd.DataFrame(all_logs)
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-cross-origin-resource-sharing', 'all_logs')

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-cross-origin-resource-sharing', 'error_logs')
            notifications_email.send_email('Exception log file generated', 'azure-cross-origin-resource-sharing' +' Exception Report', "excel", 'azure-cross-origin-resource-sharing', error_logs_df)

if __name__ == "__main__":
 get_cors_settings()
