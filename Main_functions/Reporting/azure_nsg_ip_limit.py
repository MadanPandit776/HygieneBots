import os
import logging
import sys
sys.path.append('.')
import pandas as pd
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
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

# Define the IP address limit and threshold
IP_LIMIT = 4000
THRESHOLD = 0.79 * IP_LIMIT

def process_subscription(subscription, credential):
    try:
        subscription_name = subscription.display_name
        subscription_id = subscription.subscription_id
        resource_client = ResourceManagementClient(credential, subscription_id)
        subscription_tags = resource_client.tags.get_at_scope(f"/subscriptions/{subscription_id}")
        sub_tags = subscription_tags.properties.tags
        network_client = NetworkManagementClient(credential, subscription_id)
        nsg_details = []
 
        # List all NSGs in the subscription
        nsgs = network_client.network_security_groups.list_all()
        for nsg in nsgs:
            nsg_id = nsg.id
            nsg_name = nsg.name
            nsg_location = nsg.location
            resource_group = nsg_id.split('/')[4]
            total_source_count = 0
            total_destination_count = 0
 
            # Process security rules
            for rule in nsg.security_rules:
                # Check both singular and plural forms for source and destination prefixes
                source_count = len(rule.source_address_prefixes or []) + (1 if rule.source_address_prefix else 0)
                destination_count = len(rule.destination_address_prefixes or []) + (1 if rule.destination_address_prefix else 0)

                # Count sources and destinations separately
                # source_count = len(rule.source_address_prefixes or [])
                # destination_count = len(rule.destination_address_prefixes or [])
                total_source_count += source_count
                total_destination_count += destination_count
            
            cst_time = datetime.utcnow() - timedelta(hours=6)
            cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')

            #Check if Source count IP limit greater thatn 80 percentage
            if total_source_count > THRESHOLD  :
                nsg_details.append({
                    'SubscriptionName': subscription_name,
                    'SubscriptionID': subscription_id,
                    'ResourceGroup': resource_group,
                    'NSGName': nsg_name,
                    'SourceCount': str(total_source_count),
                    'DestinationCount': 'Not Utilized',
                    'Sub_Tag': str(sub_tags) if sub_tags else "N/A",
                    'Timestamp': str(cst_time_str)
                })
            #Check if Destination count IP limit greater thatn 80 percentage
            if total_destination_count > THRESHOLD:
                 nsg_details.append({
                    'SubscriptionName': subscription_name,
                    'SubscriptionID': subscription_id,
                    'ResourceGroup': resource_group,
                    'NSGName': nsg_name,
                    'SourceCount': 'Not Utilized',
                    'DestinationCount': str(total_destination_count),
                    'Sub_Tag': str(sub_tags) if sub_tags else "N/A",
                    'Timestamp': str(cst_time_str)
                })

            logger.info(f"NSG IP limit {resource_group} in subscription {subscription_name}")
 
        return nsg_details
 
    except Exception as e:
        logger.error(f"Error processing subscription {subscription.display_name}: {e}")
        return []

def check_ip_counts_in_nsgs():
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
                logger.error(f"Invalid input subscriptions {invalid_subs}")

        all_nsg_details = []

        with ThreadPoolExecutor() as executor:
            results = executor.map(lambda sub: process_subscription(sub, credential), subscriptions)
            for result in results:
                all_nsg_details.extend(result)

        df = pd.DataFrame(all_nsg_details)
        table_name = 'azure_nsg_ip_limit'
        columns = ['SubscriptionName','SubscriptionID', 'ResourceGroup', 'NSGName', 'SourceCount', 'DestinationCount', 'Sub_Tag', 'Timestamp']
        container_name = 'azure-nsg-ip-limit'
        if all_nsg_details:
            notifications_email.send_email(container_name, container_name +' Data Report', "excel", container_name, df)
            Azure_SQL_Convertion.SQL_function(df, table_name, columns)
            Azure_Blob_Convertion.Blob_function(df, container_name, 'main_name')

    except Exception as e:
        logger.error(f"An error occurred: {e}")
    finally:
        # Retrieve logs from the handler
        all_logs = csv_error_handler.get_all_logs()
        error_logs = csv_error_handler.get_error_logs()
        # Save all logs and error logs to Blob Storage
        if all_logs:
            all_logs_df = pd.DataFrame(all_logs)
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-nsg-ip-limit', 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-nsg-ip-limit', 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('azure-nsg-ip-limit', 'azure-nsg-ip-limit' +' Error Report', "excel", 'azure-nsg-ip-limit', error_logs_df)

if __name__ == "__main__":
    check_ip_counts_in_nsgs()
