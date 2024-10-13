import logging
import os
import sys
sys.path.append('.')
import pandas as pd
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient
from azure.mgmt.network import NetworkManagementClient
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
 
# Function to get NSG details without subnets and NICs
def get_nsg_details(subscription, credential):
    nsg_details = []
    try:
        subscription_name = subscription.display_name
        print(subscription_name)
        subscription_id = subscription.subscription_id
        resource_client = ResourceManagementClient(credential, subscription_id)
        subscription_tags = resource_client.tags.get_at_scope(f"/subscriptions/{subscription_id}")
        sub_tags = subscription_tags.properties.tags
        network_client = NetworkManagementClient(credential, subscription_id)
 
        # Attempt to list all NSGs in the subscription
        nsgs = network_client.network_security_groups.list_all()
 
        # Process each NSG
        for nsg in nsgs:
            # check if no nsg and no NIC
            if not nsg.subnets and not nsg.network_interfaces:
                nsg_id = nsg.id
                nsg_name = nsg.name
                print(nsg_name)
                nsg_rg = nsg_id.split('/')[4]
                #nsg_location = nsg.location
                #nsg_tags = nsg.tags if nsg.tags else 'N/A'
                cst_time = datetime.utcnow() - timedelta(hours=6)
                cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
 
                nsg_details.append({
                    'Subscription_Name': str(subscription_name),
                    'Subscription_ID': str(subscription_id),
                    'ResourceGroup': str(nsg_rg),
                    'NSGName': str(nsg_name),
                    'Sub_Tag':  str(sub_tags) if sub_tags else "N/A",
                    'Timestamp': str(cst_time_str)
                })
                logger.info(f"NSG without subnet and network interface card {nsg_rg} in subscription {subscription_name}")
                
    except Exception as e:
        logger.error(f"Error processing NSGs for subscription {subscription.subscription_id}: {e}")
    return nsg_details
 
# Main function to check for NSGs without subnets and NICs
def nsg_without_subnets_nics():
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
                logger.error(f"invalid input subscriptions {invalid_subs}")
 
        all_nsg_details = []
 
        # Use ThreadPoolExecutor to process subscriptions concurrently
        with ThreadPoolExecutor() as executor:
            results = executor.map(lambda sub: get_nsg_details(sub, credential), subscriptions)
            for result in results:
                all_nsg_details.extend(result)
 
        # Create a DataFrame from the collected NSG details
        df = pd.DataFrame(all_nsg_details)
        table_name = 'azure_nsg_without_subnet_and_network_interface_card'
        columns = ['Subscription_Name','Subscription_ID', 'ResourceGroup', 'NSGName', 'Sub_Tag', 'Timestamp']
        container_name = 'azure-nsg-without-subnet-and-network-interface-card'
        if results:
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
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-nsg-without-subnet-and-network-interface-card', 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-nsg-without-subnet-and-network-interface-card', 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('azure-nsg-without-subnet-and-network-interface-card', 'azure-nsg-without-subnet-and-network-interface-card' +' Error Report', "excel", 'azure-nsg-without-subnet-and-network-interface-card', error_logs_df)

 
if __name__ == "__main__":
    nsg_without_subnets_nics()

