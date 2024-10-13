import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from azure.identity import ClientSecretCredential
from azure.keyvault.secrets import SecretClient
sys.path.append('.')
from concurrent.futures import ThreadPoolExecutor, as_completed
from Class.Report_handler import Azure_SQL_Convertion
from Class.Report_handler import Azure_Blob_Convertion
from Class.Logging.csv_error_handler import CSVErrorHandler
from Class.Logging import subscriptions_validations
from Class.Email import notifications_email
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from Class.Report_handler.config_param import Config
from azure.mgmt.subscription import SubscriptionClient
import pandas as pd

# Create lists to store logs
all_logs = []
error_logs = []

# Instantiate the handler
csv_error_handler = CSVErrorHandler()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(csv_error_handler)

# Azure credentials and tenant information
keyvault_url = Config.keyvault_url
credentials = DefaultAzureCredential()
secret_client = SecretClient(vault_url=keyvault_url, credential=credentials)

Tenant = Config.Tenant_ID
CLientID = Config.Client_ID
ClientSecret = Config.Client_Secret

GetTenant = secret_client.get_secret(Tenant)
GetCLientID = secret_client.get_secret(CLientID)
GetClientSecret = secret_client.get_secret(ClientSecret)

ValueTenant = GetTenant.value
ValueCLientID = GetCLientID.value
VAlueClientSecret = GetClientSecret.value

# Authentication
credential = ClientSecretCredential(tenant_id=ValueTenant, client_id=ValueCLientID, client_secret=VAlueClientSecret)

def process_subscription(subscription):
    try:
        #credential = DefaultAzureCredential()
        network_client = NetworkManagementClient(credential, subscription.subscription_id)
        data = []
        #List of Application Getways
        app_gateways = network_client.application_gateways.list_all()
        for app_gateway in app_gateways:
            resource_group_name = app_gateway.id.split('/')[4]

            backend_health_pools = network_client.application_gateways.begin_backend_health(
                resource_group_name=resource_group_name,
                application_gateway_name=app_gateway.name
            ).result()
            # Check APPGW backend adress servers if no bacnkend servers show server as "N/A"
            if backend_health_pools.backend_address_pools is None or not backend_health_pools.backend_address_pools:
                cst_time = datetime.utcnow() - timedelta(hours=6)
                cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
                data.append({
                    "SubscriptionName": str(subscription.display_name),
                    "Subscription": str(subscription.subscription_id),
                    "ResourceGroup": str(resource_group_name),
                    "AppGWName": str(app_gateway.name),
                    "App_Gw_Location": str(app_gateway.location),
                    "BackendPoolName": "No backend pools",
                    "Server": "N/A",
                    "HealthStatus": "No backend servers",
                    'Timestamp': str(cst_time_str)
                })
                logger.info(f"No backend servers for {app_gateway.name} in subscription {subscription.display_name}")
                
            
            else:
                for backend_health_pool in backend_health_pools.backend_address_pools:
                    backend_pool_id = backend_health_pool.backend_address_pool.id
                    backend_pool_name = backend_pool_id.split('/')[-1]
                    
                    for healthstatus in backend_health_pool.backend_http_settings_collection:
                        # Check APPGW backend adress servers if no bacnkend servers show server as "N/A"
                        if not healthstatus.servers: 
                            print(backend_pool_name)
                            cst_time = datetime.utcnow() - timedelta(hours=6)
                            cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
                            data.append({
                                "SubscriptionName": str(subscription.display_name),
                                "Subscription": str(subscription.subscription_id),
                                "ResourceGroup": str(resource_group_name),
                                "AppGWName": str(app_gateway.name),
                                "App_Gw_Location": str(app_gateway.location),
                                "BackendPoolName": str(backend_pool_name),
                                "Server": "N/A",
                                "HealthStatus": "No backend servers",
                                'Timestamp': str(cst_time_str)
                            })
                            logger.info(f"No backend servers for pool {backend_pool_name} in {app_gateway.name} (subscription {subscription.display_name})")
                         # Check APPGW backend adress servers if having bacnkend servers show server as "servers in reports"    
                        else:
                            for serverhealth in healthstatus.servers:
                                cst_time = datetime.utcnow() - timedelta(hours=6)
                                cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
                                data.append({
                                    "SubscriptionName": str(subscription.display_name),
                                    "Subscription": str(subscription.subscription_id),
                                    "ResourceGroup": str(resource_group_name),
                                    "AppGWName": str(app_gateway.name),
                                    "App_Gw_Location": str(app_gateway.location),
                                    "BackendPoolName": str(backend_pool_name),
                                    "Server": str(serverhealth.address),
                                    "HealthStatus": str(serverhealth.health),
                                    'Timestamp': str(cst_time_str)
                                })
                                logger.info(f"Found Health status for {app_gateway.name} in subscription {subscription.display_name}")
        return data
    except Exception as e:
        logger.error(f"An error occurred during subscription {subscription.display_name} processing: {e}")
        print(f"An error occurred during subscription {subscription.display_name} processing: {e}")
        return []

def get_app_gw_health_report():
    try:
        credential = DefaultAzureCredential(exclude_managed_identity_credential=True)
        subscription_client = SubscriptionClient(credential)

        user_input = sys.argv[1] if len(sys.argv) > 1 else "all"

        if (user_input.lower() == "all"):
            subscriptions = subscription_client.subscriptions.list()
        else:
            subscription_names = [s.strip() for s in user_input.split(",")]
            subscriptions = [s for s in subscription_client.subscriptions.list() if s.display_name in subscription_names]
            valid_subs, invalid_subs = subscriptions_validations.check_valid_subscription_names(subscription_names)
            if invalid_subs:
                logger.error(f"invalid input subscriptions {invalid_subs}")

        data = []

        with ThreadPoolExecutor() as executor:
            results = executor.map(process_subscription, subscriptions)
            for result in results:
                data.extend(result)

        df = pd.DataFrame(data)
        table_name = 'azure_application_gateway_health_status'
        container_name = 'azure-application-gateway-health-status'
        columns = ['SubscriptionName','Subscription', 'ResourceGroup', 'AppGWName', 'App_Gw_Location', 'BackendPoolName','Server', 'HealthStatus', 'Timestamp']
        if data:
            Azure_SQL_Convertion.SQL_function(df, table_name, columns)
            Azure_Blob_Convertion.Blob_function(df, container_name, 'main_name')
            notifications_email.send_email(container_name, container_name +' Data Report', "excel", container_name, df)

    except Exception as e:
        logger.error(f"An error occurred: {e}")
        print(f"An error occurred: {e}")
    finally:
        # Retrieve logs from the handler
        all_logs = csv_error_handler.get_all_logs()
        error_logs = csv_error_handler.get_error_logs()
        # Save all logs and error logs to Blob Storage
        if all_logs:
            all_logs_df = pd.DataFrame(all_logs)
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-application-gateway-health-status', 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-application-gateway-health-status', 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('Exception log file generated', 'azure-application-gateway-health-status' +' Exception Report', "excel", 'azure-application-gateway-health-status', error_logs_df)

if __name__ == "__main__":
    get_app_gw_health_report()
