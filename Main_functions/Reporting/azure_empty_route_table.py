import logging
import os
import sys
sys.path.append('.')
import pandas as pd
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from Class.Email import notifications_email
from Class.Report_handler import Azure_SQL_Convertion
from Class.Report_handler import Azure_Blob_Convertion
from Class.Logging.csv_error_handler import CSVErrorHandler
from Class.Logging import subscriptions_validations

# Create lists to store logs
all_logs = []
error_logs = []

# Instantiate the handler
csv_error_handler = CSVErrorHandler()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(csv_error_handler)
 
# Function to get route table details without subnets
def get_route_table_details(subscription, credential):
    route_table_details = []
    try:
        subscription_name = subscription.display_name
        print(subscription_name)
        subscription_id = subscription.subscription_id
        resource_client = ResourceManagementClient(credential, subscription_id)
        network_client = NetworkManagementClient(credential, subscription_id)
        resource_client = ResourceManagementClient(credential, subscription_id)
        subscription_tags = resource_client.tags.get_at_scope(f"/subscriptions/{subscription_id}")
        sub_tags = subscription_tags.properties.tags
        
        # Iterate over all the resource groups
        for resource_group in resource_client.resource_groups.list():
            # Iterate over all the route tables
            for route_table in network_client.route_tables.list(resource_group.name):
                # Check if the route table has no subnets
                if not route_table.subnets:
                    route_table_name = route_table.name
                    print(route_table_name)
                    route_table_location = route_table.location
                    #route_table_tags = route_table.tags if route_table.tags else 'N/A'
                    cst_time = datetime.utcnow() - timedelta(hours=6)
                    cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
 
                    route_table_details.append({
                        'SubscriptionName': str(subscription_name),
                        'Subscription_ID': str(subscription_id),
                        'RouteTableName': str(route_table_name),
                        'ResourceGroup': str(resource_group.name),
                        'Sub_Tag': str(sub_tags) if sub_tags else "N/A",
                        'Timestamp': str(cst_time_str)   
                    })
                    logger.info(f"Route table without Subnet {route_table_name} in subscription {subscription_name}")
    except Exception as e:
        logger.error(f"Error processing route tables for subscription {subscription.subscription_id}: {e}")
    return route_table_details
 
# Main function to check for route tables without subnets
def route_table_without_subnets():
    try:
        credential = DefaultAzureCredential()
        subscription_client = SubscriptionClient(credential)
 
        # Determine the subscriptions to process based on user input
        user_input = sys.argv[1] if len(sys.argv) > 1 else "all"
 
        if user_input.lower() == "all":
            subscriptions = subscription_client.subscriptions.list()
        else:
            subscription_names = [s.strip() for s in user_input.split(",")]
            subscriptions = [s for s in subscription_client.subscriptions.list() if s.display_name in subscription_names]
            valid_subs, invalid_subs = subscriptions_validations.check_valid_subscription_names(subscription_names)
            if invalid_subs:
                logger.error(f"Invalid input subscriptions {invalid_subs}")
 
        all_route_table_details = []
 
        # Use ThreadPoolExecutor to process subscriptions concurrently
        with ThreadPoolExecutor() as executor:
            results = executor.map(lambda sub: get_route_table_details(sub, credential), subscriptions)
            for result in results:
                all_route_table_details.extend(result)
 
        # Create a DataFrame from the collected route table details
        df = pd.DataFrame(all_route_table_details)
        table_name = 'azure_empty_route_table'
        columns = ['SubscriptionName','Subscription_ID', 'RouteTableName', 'Resource_Name', 'Sub_Tag', 'Timestamp']
        container_name = 'azure-empty-route-table'
        if all_route_table_details:
            notifications_email.send_email(container_name, container_name +' Data Report', "excel", container_name, df)
            Azure_SQL_Convertion.SQL_function(df, table_name, columns)
            Azure_Blob_Convertion.Blob_function(df, container_name, 'main_name')
 
    except Exception as e:
        logger.error(f"An error occurred in the main function: {e}")
    
    finally:
        # Retrieve logs from the handler
        all_logs = csv_error_handler.get_all_logs()
        error_logs = csv_error_handler.get_error_logs()
        # Save all logs and error logs to Blob Storage
        if all_logs:
            all_logs_df = pd.DataFrame(all_logs)
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-empty-route-table', 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-empty-route-table', 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('azure-empty-route-table', 'azure-empty-route-table' +' Error Report', "excel", 'azure-empty-route-table', error_logs_df)

 
if __name__ == "__main__":
    route_table_without_subnets()