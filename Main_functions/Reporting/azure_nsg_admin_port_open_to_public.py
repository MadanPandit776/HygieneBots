import logging
from azure.mgmt.network import NetworkManagementClient
import pandas as pd
from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient
from azure.identity import DefaultAzureCredential
import sys
sys.path.append('.')
import os
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

 
def process_nsg_rule(sub, credential):
    results = []
    try:
        subscription_id = sub.subscription_id
        subscription_name = sub.display_name
        resource_client = ResourceManagementClient(credential, subscription_id)
        subscription_tags = resource_client.tags.get_at_scope(f"/subscriptions/{subscription_id}")
        sub_tags = subscription_tags.properties.tags
        network_client = NetworkManagementClient(credential, sub.subscription_id)
        nsgs = network_client.network_security_groups.list_all()
       # Iterate every NSG
        for nsg in nsgs:
            nsg_name = nsg.name
            nsg_rg = nsg.id.split('/')[4]
            nsg_rules = nsg.security_rules  
           # Iterate eery rule  
            for rule in nsg_rules:
                cst_time = datetime.utcnow() - timedelta(hours=6)
                cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
                # check condition like direction should be Inbound and access should be Allow and admin porta "'3389', '22', '445', '139'" and priority greater than 3500
                if (rule.direction == "Inbound" and
                    rule.access == "Allow" and 
                    rule.destination_port_range in ['3389', '22', '445', '139']) and rule.priority < 3500 and rule.source_address_prefix  == "*":
                    results.append({
                        "SubscriptionName": subscription_name,
                        "Subscription_ID": subscription_id,
                        "NSG_Name": nsg_name,
                        "Nsg_Rg": nsg_rg,
                        "Rule_Name": rule.name,
                        "Direction": rule.direction,
                        "Port": str(rule.destination_port_range),
                        "Priority_Number": str(rule.priority),
                        'Sub_Tag': str(sub_tags) if sub_tags else "N/A",
                        'Timestamp': cst_time_str
                    })
                    logger.info(f"Network security group admin port open to public {nsg_rg} in subscription {subscription_name}")
                # check condition like direction should be Outbound and access should be Allow and admin porta "'3389', '22', '445', '139'" and priority greater than 3500
                # Check for outbound rules
                if (rule.direction == "Outbound" and 
                    rule.access == "Allow" and 
                    rule.destination_port_range in ['3389', '22', '445', '139']) and rule.priority < 3500 and rule.destination_address_prefix == "*":
                    results.append({
                        "SubscriptionName": subscription_name,
                        "Subscription_ID": subscription_id,
                        "NSG_Name": nsg_name,
                        "Nsg_Rg": nsg_rg,
                        "Rule_Name": rule.name,
                        "Direction": rule.direction,
                        "Port": str(rule.destination_port_range),
                        "Priority_Number": str(rule.priority),
                        'Sub_Tag': str(sub_tags) if sub_tags else "N/A",
                        'Timestamp': cst_time_str
                    })  
    except Exception as subscription_loop_exception:
        logger.error(f"An error occurred during subscription loop: {subscription_loop_exception}")
 
    return results
 
def nsg_open_specific_ports():
    try:
        credential = DefaultAzureCredential()
        subscription_client = SubscriptionClient(credential)
 
        results = []
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
            for sub in subscriptions:
                # Process each subscription concurrently
                results.extend(executor.submit(process_nsg_rule, sub, credential).result())
        
        # Convert the results to a DataFrame
        df = pd.DataFrame(results)
        table_name = 'azure_nsg_admin_port_open_to_public'
        
        columns = ['SubscriptionName','Subscription_ID', 'NSG_Name','Nsg_Rg', 'Rule_Name', 'Direction','Port', 'Priority_Number', 'Sub_Tag', 'Timestamp']
        container_name = 'azure-nsg-admin-port-open-to-public'
 
        if results:
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
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-nsg-admin-port-open-to-public', 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-nsg-admin-port-open-to-public', 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('azure-nsg-admin-port-open-to-public', 'azure-nsg-admin-port-open-to-public' +' Error Report', "excel", 'azure-nsg-admin-port-open-to-public', error_logs_df)

 
# Call the function
nsg_open_specific_ports()

