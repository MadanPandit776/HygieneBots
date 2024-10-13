import logging
import os
import sys
sys.path.append('.')
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
import pandas as pd
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.monitor import MonitorManagementClient

# Import your custom classes and functions
from Class.Report_handler import Azure_SQL_Convertion
from Class.Report_handler import Azure_Blob_Convertion
from Class.Logging.csv_error_handler import CSVErrorHandler
from Class.Email import notifications_email
from Class.Logging import subscriptions_validations

# Initialize logging and other components
csv_error_handler = CSVErrorHandler()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(csv_error_handler)

def process_load_balancer(subscription, credential):
    try:
        subscription_id = subscription.subscription_id
        subscription_name = subscription.display_name
        network_client = NetworkManagementClient(credential, subscription_id)
        monitor_client = MonitorManagementClient(credential, subscription_id)
        
        unhealthy_pools = []

        for lb in network_client.load_balancers.list_all():
            resource_group_name = lb.id.split('/')[4]
            lb_name = lb.name
            location = lb.location
            lb_id = lb.id
            cst_time = datetime.utcnow() - timedelta(hours=6)
            cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
            
            backend_pools = lb.backend_address_pools
            for backend_pool in backend_pools:
                health_status = None
                average_value = None
                backend_pool_name = backend_pool.name

                for backend_address in backend_pool.load_balancer_backend_addresses:
                 privateIP = backend_address.ip_address
                 NicIP = backend_address.network_interface_ip_configuration
                 if privateIP is not None:
                    metrics = monitor_client.metrics.list(
                        lb_id,
                        timespan='PT1H',
                        metricnames='DipAvailability',
                        aggregation='Average',
                        filter=f"BackendIPAddress eq '{privateIP}'"
                    )
 
                    for metric in metrics.value:
                        for timeseries in metric.timeseries:
                            for data in timeseries.data:
                                average_value = data.average
                                if metric.name.localized_value == 'Health Probe Status':
                                    if average_value is None:
                                        health_status = None
                                    elif average_value == 0:
                                        health_status = "unhealthy"
                                    else:
                                        health_status = "healthy"
               
                    unhealthy_pools.append({
                        'SubscriptionName': str(subscription_name),
                        'Subscription': str(subscription_id),
                        'ResourceGroup': str(resource_group_name),
                        'LoadBalancerName': str(lb_name),
                        'Lb_Location': str(location),
                        'BackendPoolName': str(backend_pool_name),
                        'BackendAddress': str(privateIP),
                        'HealthStatus': str(health_status),
                        'Health_Probe_Status': str(average_value),
                        'Timestamp': str(cst_time_str)
                    })
       
                 if NicIP is not None:
                   nic_id = NicIP.id  
                   resource_group = nic_id.split('/')[4]
                   nic_name = nic_id.split('/')[8]  
                   nic_info = network_client.network_interfaces.get(resource_group, nic_name)
                   ip_configuration = nic_info.ip_configurations[0]
                   ip_address = ip_configuration.private_ip_address  # Use private_ip_address or public_ip_address as needed
 
                   metrics = monitor_client.metrics.list(
                        lb_id,
                        timespan='PT1H',
                        metricnames='DipAvailability',
                        aggregation='Average',
                        filter=f"BackendIPAddress eq '{ip_address}'"
                    )
 
                   for metric in metrics.value:
                        for timeseries in metric.timeseries:
                            for data in timeseries.data:
                                average_value = data.average
                                if metric.name.localized_value == 'Health Probe Status':
                                    if average_value is None:
                                        health_status = None
                                    elif average_value == 0:
                                        health_status = "unhealthy"
                                    else:
                                        health_status = "healthy"
               
                   unhealthy_pools.append({
                        'SubscriptionName': str(subscription_name),
                        'Subscription': str(subscription_id),
                        'ResourceGroup': str(resource_group_name),
                        'LoadBalancerName': str(lb_name),
                        'Lb_Location': str(location),
                        'BackendPoolName': str(backend_pool_name),
                        'BackendAddress': str(ip_address),
                        'HealthStatus': str(health_status),
                        'Health_Probe_Status': str(average_value),
                        'Timestamp': str(cst_time_str)
                    })
 

                

                 logger.info(f"Processing LoadBalancer {lb_name} - Backend Pool {backend_pool_name}")
        
        return unhealthy_pools

    except Exception as e:
        logger.error(f"An error occurred during subscription {subscription.display_name} processing: {e}")
        return []

def check_average_health_probe_status():
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

        unhealthy_pools = []

        with ThreadPoolExecutor() as executor:
            results = executor.map(lambda sub: process_load_balancer(sub, credential), subscriptions)
            for result in results:
                unhealthy_pools.extend(result)

        df = pd.DataFrame(unhealthy_pools)
        
        # Save results to Azure SQL and Blob Storage
        table_name = 'azure_load_balancer_health_status'
        container_name = 'azure-load-balancer-health-status'
        columns = ['SubscriptionName', 'Subscription', 'ResourceGroup', 'LoadBalancerName', 'Lb_Location', 'BackendPoolName', 'BackendIPAddress', 'HealthStatus', 'Health_Probe_Status', 'Timestamp']
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
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-load-balancer-health-status', 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-load-balancer-health-status', 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('Exception log file generated', 'azure-load-balancer-health-status'+' Exception Report', "excel", 'azure-load-balancer-health-status', error_logs_df)

if __name__ == "__main__":
    check_average_health_probe_status()
