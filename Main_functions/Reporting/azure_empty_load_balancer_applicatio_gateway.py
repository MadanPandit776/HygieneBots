import logging
import os
import sys
import pandas as pd
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import SubscriptionClient
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
 
# Import custom classes and functions
sys.path.append('.')
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
 
def process_subscription(subscription, credential):
    try:
        subscription_name = subscription.display_name
        subscription_id = subscription.subscription_id
        network_client = NetworkManagementClient(credential, subscription_id)
        
        empty_resources = []
 
        # Check empty load balancers
        load_balancers = network_client.load_balancers.list_all()
        for lb in load_balancers:
            lb_name = lb.name
            lb_rg = lb.id.split('/')[4]
            location = lb.location
            if not lb.load_balancing_rules and not lb.inbound_nat_rules and not lb.outbound_rules:
                cst_time = datetime.utcnow() - timedelta(hours=6)
                cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
 
                empty_resources.append({
                    'SubscriptionName': str(subscription_name),
                    'Subscription': str(subscription_id),
                    'ResourceGroup': str(lb_rg),
                    'Resource_Name': str(lb_name),
                    'Resource_type': str(lb.type),
                    'Resource_Location': str(location),
                    'Backend_Pool_Name': "N/A",
                    'Empty_resources': 'Yes',
                    'Timestamp': str(cst_time_str)
                })
                logger.info(f"Empty Load Balancer {lb_name} under subscription: {subscription_name}")
 
        # Check empty application gateways
        app_gateways = network_client.application_gateways.list_all()
        for appgw in app_gateways:
            appgw_name = appgw.name
            appgw_rg = appgw.id.split('/')[4]
            location = appgw.location
            all_pools_empty = True  # Assume all backend pools are empty initially
            backend_pool_names = []

            for backend_pool in appgw.backend_address_pools:
                backend_pool_name = backend_pool.name  # Get the backend pool name
                backend_pool_names.append(backend_pool.name)
                if (backend_pool.backend_addresses or 
                   backend_pool.backend_ip_configurations):
                   all_pools_empty = False
                   break  # Exit the loop early if any non-empty backend pool is found
            if all_pools_empty:       
                    backend_pool_names_str = ", ".join(backend_pool_names)
                    cst_time = datetime.utcnow() - timedelta(hours=6)
                    cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
                    #num_targets = len(backend_pool.backend_ip_configurations) if backend_pool.backend_ip_configurations else 0
                    #if num_targets == 0:
                    empty_resources.append({
                        'SubscriptionName': str(subscription_name),
                        'Subscription': str(subscription_id),
                        'ResourceGroup': str(appgw_rg),
                        'Resource_Name': str(appgw_name),
                        'Resource_type': str(appgw.type),
                        'Resource_Location': str(location),
                        'Backend_Pool_Name': str(backend_pool_names_str),  # Include backend pool name here
                        'Empty_resources': 'Yes',
                        'Timestamp': str(cst_time_str)
                     })
                    logger.info(f"Empty ApplicationGW {appgw_name} - Backend Pool {backend_pool_name} under subscription: {subscription_name}")
 
        return empty_resources
 
    except Exception as e:
        logger.error(f"An error occurred during subscription {subscription.display_name} processing: {e}")
        return []
 
def check_empty_resources():
    try:
        credential = DefaultAzureCredential()
        subscription_client = SubscriptionClient(credential)
 
        user_input = sys.argv[1] if len(sys.argv) > 1 else "all"
 
        if user_input.lower() == "all":
            subscriptions = subscription_client.subscriptions.list()
        else:
            subscription_names = [s.strip() for s in user_input.split(",")]
            subscriptions = [s for s in subscription_client.subscriptions.list() if s.display_name in subscription_names]
            valid_subs, invalid_subs = subscriptions_validations.check_valid_subscription_names(subscription_names)
            if invalid_subs:
              logger.error(f"invalid input subscriptions {invalid_subs}")
 
        empty_resources = []
 
        with ThreadPoolExecutor() as executor:
            results = executor.map(lambda sub: process_subscription(sub, credential), subscriptions)
            for result in results:
                empty_resources.extend(result)
 
        df = pd.DataFrame(empty_resources)
        
        # Save results to Azure SQL and Blob Storage
        table_name = 'azure_empty_load_balancer_application_gateway'
        container_name = 'azure-empty-load-balancer-application-gateway'
        
        columns = ['SubscriptionName', 'Subscription', 'ResourceGroup', 'Resource_Name', 'Resource_type', 'Resource_Location', 'Backend_Pool_Name', 'Empty_resources', 'Timestamp']
        
        if not df.empty:
            Azure_SQL_Convertion.SQL_function(df, table_name, columns)
            Azure_Blob_Convertion.Blob_function(df, container_name, 'main_name')
            notifications_email.send_email(container_name, container_name + ' Data Report', "excel", container_name, df)
 
    except Exception as e:
        logger.error(f"An error occurred: {e}")
    finally:
        # Retrieve logs from the handler
        all_logs = csv_error_handler.get_all_logs()
        error_logs = csv_error_handler.get_error_logs()
        
        # Save all logs and error logs to Blob Storage
        if all_logs:
            all_logs_df = pd.DataFrame(all_logs)
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-empty-load-balancer-application-gateway', 'all_logs')
            logger.info(f"All logs generated for CSV")
 
        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-empty-load-balancer-application-gateway', 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('Exception log file generated', 'azure-empty-load-balancer-application-gateway' + ' Exception Report', "excel", 'azure-empty-load-balancer-application-gateway', error_logs_df)
 
if __name__ == "__main__":
    check_empty_resources()
 