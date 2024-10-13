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

 
# Define the NSG Rule limit and threshold
Rule_LIMIT = 1000
THRESHOLD = 0.79 * Rule_LIMIT
 
def process_subscription(subscription, credential):
    try:
        subscription_name = subscription.display_name
        print(subscription_name)
        subscription_id = subscription.subscription_id
        resource_client = ResourceManagementClient(credential, subscription_id)
        subscription_tags = resource_client.tags.get_at_scope(f"/subscriptions/{subscription_id}")
        sub_tags = subscription_tags.properties.tags
        network_client = NetworkManagementClient(credential, subscription_id)
        nsg_rule_limits = []
 
        # Check NSG rule limits
        nsgs = network_client.network_security_groups.list_all()
        for nsg in nsgs:
            nsg_name = nsg.name
            nsg_rg = nsg.id.split('/')[4]

            # Count inbound and outbound rules
            inbound_rules_count = len([rule for rule in nsg.security_rules if rule.direction == 'Inbound'])
            outbound_rules_count = len([rule for rule in nsg.security_rules if rule.direction == 'Outbound'])
            #print(f" rg {nsg_rg} nsg {nsg_name} inboundrule {inbound_rules_count} outboundrule {outbound_rules_count} ")
            total_rules_count = inbound_rules_count + outbound_rules_count
 
            # Check if the total rules exceed 80% of the limit (1000 rules)
            if total_rules_count > THRESHOLD:
                cst_time = datetime.utcnow() - timedelta(hours=6)
                cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
 
                nsg_rule_limits.append({
                    'SubscriptionName': str(subscription_name),
                    'SubscriptionID': str(subscription_id),
                    'ResourceGroup': str(nsg_rg),
                    'NSG_Name': str(nsg_name),
                    'TotalRules_Count': str(total_rules_count),
                    'Sub_Tag': str(sub_tags) if sub_tags else "N/A",
                    'Timestamp': str(cst_time_str)
                })
                logger.info(f"NSG rule limit {nsg_rg} in subscription {subscription_name}")
 
        return nsg_rule_limits
 
    except Exception as e:
        logger.error(f"An error occurred during subscription {subscription.display_name} processing: {e}")
        return []
 
def check_nsg_rule_limits():
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
 
        nsg_rule_limits = []
 
        with ThreadPoolExecutor() as executor:
            results = executor.map(lambda sub: process_subscription(sub, credential), subscriptions)
            for result in results:
                nsg_rule_limits.extend(result)
 
        df = pd.DataFrame(nsg_rule_limits)
        table_name = 'azure_nsg_rule_limit'
        columns = ['SubscriptionName','SubscriptionID', 'ResourceGroup', 'NSG_Name', 'TotalRules_Count', 'Sub_Tag', 'Timestamp']
        container_name = 'azure-nsg-rule-limit'
        if nsg_rule_limits:
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
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-nsg-rule-limit', 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-nsg-rule-limit', 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('azure-nsg-rule-limit', 'azure-nsg-rule-limit' +' Error Report', "excel", 'azure-nsg-rule-limit', error_logs_df)

 
if __name__ == "__main__":
    check_nsg_rule_limits()