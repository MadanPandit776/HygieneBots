import logging
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.web import WebSiteManagementClient
import pandas as pd
import sys
sys.path.append('.')
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from Class.Report_handler import Azure_SQL_Convertion
from Class.Report_handler import Azure_Blob_Convertion
from Class.Logging.csv_error_handler import CSVErrorHandler
from Class.Email import notifications_email
from Class.Logging import subscriptions_validations

# Create lists to store logs
all_logs = []
error_logs = []

csv_error_handler = CSVErrorHandler()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(csv_error_handler)

def process_subscription(subscription):
    credential = DefaultAzureCredential()
    subscription_id = subscription.subscription_id
    subscription_name = subscription.display_name
    logger.info(f"Processing subscription: {subscription_name} (ID: {subscription_id})")
    web_client = WebSiteManagementClient(credential, subscription_id)
    https_only_apps = []

    try:
        apps = list(web_client.web_apps.list())

        for app in apps:
            resource_group_name = app.resource_group
            app_name = app.name
            app_id = app.id
            app_kind = app.kind
            location = app.location

            try:
                app_config = web_client.web_apps.get(resource_group_name, app_name)
                state = app.state
                https_only = app_config.https_only
                cst_time = datetime.utcnow() - timedelta(hours=6)
                cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
                print(app_name)

                if not https_only:
                    https_only_apps.append({
                        'SubscriptionName': subscription_name,
                        'Subscription': subscription_id,
                        'WebAppAccount': app_id,
                        'App_Name': app_name,
                        'location': location,
                        'App_Type': app_kind,
                        'HTTPS_only': str(https_only),
                        'state': state,
                        'Timestamp': cst_time_str
                    })
                    logger.info(f"Https not enabled for: {app_name} in subscription {subscription_name}")
            except Exception as e:
                logger.error(f"Error processing app {app_name} in subscription {subscription_name}: {str(e)}")
                continue  # Skip the app and continue with the next one

    except Exception as e:
        logger.error(f"Error processing subscription {subscription_name}: {str(e)}")
        return []

    return https_only_apps

def check_https_only():
    try:
        credential = DefaultAzureCredential()
        subscription_client = SubscriptionClient(credential)
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
            results = executor.map(process_subscription, subscriptions)
            https_only_apps = []
            for result in results:
                https_only_apps.extend(result)

        df = pd.DataFrame(https_only_apps)
        if https_only_apps:
            table_name = 'azure_services_https_not_enabled_with_webapp_functionapp_api'
            container_name = 'azure-services-https-not-enabled-with-webapp-functionapp-api'
            columns = ['SubscriptionName', 'Subscription', 'WebAppAccount', 'App_Name', 'location', 'App_Type', 'HTTPS_only', 'state', 'Timestamp']
            Azure_SQL_Convertion.SQL_function(df, table_name, columns)
            Azure_Blob_Convertion.Blob_function(df, container_name, 'main_name')
            notifications_email.send_email(container_name, 'Bot Report : ' + container_name, "excel", container_name, df)

    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")

    finally:
        all_logs = csv_error_handler.get_all_logs()
        error_logs = csv_error_handler.get_error_logs()
        if all_logs:
            all_logs_df = pd.DataFrame(all_logs)
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-services-https-not-enabled-with-webapp-functionapp-api', 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-services-https-not-enabled-with-webapp-functionapp-api', 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('Exception log file generated', 'azure-services-https-not-enabled-with-webapp-functionapp-api' + ' Exception Report', "excel", 'azure-services-https-not-enabled-with-webapp-functionapp-api', error_logs_df)

# Call the function
check_https_only()
