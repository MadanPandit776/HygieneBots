import logging
import os
import sys
sys.path.append('.')
import pandas as pd
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import SubscriptionClient
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

def process_subscription(subscription, credential):
    try:
        subscription_name = subscription.display_name
        subscription_id = subscription.subscription_id
        resource_client = ResourceManagementClient(credential, subscription_id)
        subscription_tags = resource_client.tags.get_at_scope(f"/subscriptions/{subscription_id}")
        sub_tags = subscription_tags.properties.tags
        network_client = NetworkManagementClient(credential, subscription_id)
        mismatched_resources = []
 
        # Check NSGs not mapped to correct Network Resource Groups
        nsgs = network_client.network_security_groups.list_all()
        for nsg in nsgs:
            nsg_name = nsg.name
            nsg_rg = nsg.id.split('/')[4]
            location = nsg.location
 
            # Logic to check if 'nsg' is not in the resource group name
            if not nsg_rg.startswith("pep-network") and not "nsg" in nsg_rg:
                #print(nsg_name)
                cst_time = datetime.utcnow() - timedelta(hours=6)
                cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
 
                mismatched_resources.append({
                    'SubscriptionName': str(subscription_name),
                    'Subscription_ID': str(subscription_id),
                    'Resource_Type': "NSG",
                    'Resource_Name': str(nsg_name),
                    'Location': str(location),
                    'RG_Name': str(nsg_rg),
                    'Sub_Tag': str(sub_tags) if sub_tags else "N/A",
                    'Timestamp': str(cst_time_str), 
                })
                logger.info(f"Not mapped with correct NSG RG {nsg_rg} in subscription {subscription_name}")

 
        # Check ASGs not mapped to correct Network Resource Groups
        asgs = network_client.application_security_groups.list_all()
        for asg in asgs:
            asg_name = asg.name
            asg_rg = asg.id.split('/')[4]
            location = asg.location
 
            # check if 'nsg' is not in the resource group name
            if not asg_rg.startswith("pep-network") and not "nsg" in asg_rg:
                print(f"asg rg {asg_rg}, asg name {asg_name}")
                cst_time = datetime.utcnow() - timedelta(hours=6)
                cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
 
                mismatched_resources.append({
                    'SubscriptionName': str(subscription_name),
                    'Subscription_ID': str(subscription_id),
                    'Resource_Type': "ASG",
                    'Resource_Name': str(asg_name),
                    'Location': str(location),
                    'RG_Name': str(asg_rg),
                    'Sub_Tag': str(sub_tags) if sub_tags else "N/A",
                    'Timestamp': str(cst_time_str),
                    })
                logger.info(f"Not mapped with correct ASG RG {asg_rg} in subscription {subscription_name}")

                   
 
        return mismatched_resources
    
    except Exception as e:
        logger.error(f"An error occurred during subscription {subscription.display_name} processing: {e}")

        return []
 
def check_mismatched_resources():
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

 
        mismatched_resources = []
 
        with ThreadPoolExecutor() as executor:
            results = executor.map(lambda sub: process_subscription(sub, credential), subscriptions)
            
            for result in results:
                mismatched_resources.extend(result)
 
        df = pd.DataFrame(mismatched_resources)
        table_name = 'azure_asg_nsg_not_mapped_with_correct_resource_group'
        columns = ['SubscriptionName','Subscription_ID', 'Resource_Type', 'Resource_Name', 'Location', 'RG_Name','Sub_Tag', 'Timestamp']
        container_name = 'azure-asg-nsg-not-mapped-with-correct-resource-group'
        if mismatched_resources:
            notifications_email.send_email(container_name, container_name +' Data Report', "excel", container_name, df)
            Azure_SQL_Convertion.SQL_function(df, table_name, columns)
            Azure_Blob_Convertion.Blob_function(df, container_name, 'main_name')
 
 
    except Exception as e:
        logger.error(e)
    finally:
        # Retrieve logs from the handler
        all_logs = csv_error_handler.get_all_logs()
        error_logs = csv_error_handler.get_error_logs()
        # Save all logs and error logs to Blob Storage
        if all_logs:
            all_logs_df = pd.DataFrame(all_logs)
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-asg-nsg-not-mapped-with-correct-resource-group', 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-asg-nsg-not-mapped-with-correct-resource-group', 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('azure-asg-nsg-not-mapped-with-correct-resource-group', 'azure-asg-nsg-not-mapped-with-correct-resource-group' +' Error Report', "excel", 'azure-asg-nsg-not-mapped-with-correct-resource-group', error_logs_df)

 
if __name__ == "__main__":
    check_mismatched_resources()

 