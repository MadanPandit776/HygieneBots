import logging
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.network import NetworkManagementClient
import pandas as pd
from azure.mgmt.resource import SubscriptionClient
from azure.identity import DefaultAzureCredential
import sys
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor

sys.path.append('.')
from Class.Report_handler import Azure_SQL_Convertion
from Class.Report_handler import Azure_Blob_Convertion
from Class.Logging.csv_error_handler import CSVErrorHandler
from Class.Email import notifications_email
from Class.Logging import subscriptions_validations

# Instantiate the handler
csv_error_handler = CSVErrorHandler()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(csv_error_handler)

# Create lists to store logs
all_logs = []
error_logs = []

def extract_asg_names(asg_list):
    # Helper function to extract ASG names
    if asg_list:
        return [asg.id.split('/')[-1] for asg in asg_list]
    return None

def get_address_prefixes(rule):
    # Helper function to return address prefixes or ASG names if present
    source_address_prefix = rule.source_address_prefix or rule.source_address_prefixes or extract_asg_names(rule.source_application_security_groups)
    destination_address_prefix = rule.destination_address_prefix or rule.destination_address_prefixes or extract_asg_names(rule.destination_application_security_groups)
    return source_address_prefix, destination_address_prefix

def process_nsg_rule(sub, credential):
    results = []
    try:
        subscription_id = sub.subscription_id
        subscription_name = sub.display_name
        print(subscription_name)
        resource_client = ResourceManagementClient(credential, sub.subscription_id)
        network_client = NetworkManagementClient(credential, sub.subscription_id)

        for resource_group in resource_client.resource_groups.list():
            try:
                for nsg in network_client.network_security_groups.list(resource_group.name):
                    for rule in nsg.security_rules:
                        cst_time = datetime.utcnow() - timedelta(hours=6)
                        cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')

                        source_address_prefix, destination_address_prefix = get_address_prefixes(rule)

                        # Check for inbound rules
                        if (rule.direction == "Inbound" and 
                            rule.access == "Allow" and 
                            rule.priority < 3600 and 
                            ("*" in source_address_prefix or "*" in destination_address_prefix)):
                            print(f"Inbound rule: {rule.name} in NSG {nsg.name} in resource group {resource_group.name} meets the criteria.")
                            results.append({
                                "SubscriptionName": sub.display_name,
                                "Subscription": sub.subscription_id,
                                "ResourceGroup": resource_group.name,
                                "NSG_Name": nsg.name,
                                "NSG_Location": nsg.location,
                                "Direction": rule.direction,
                                "Rule_Name": rule.name,
                                "source_address_prefix": str(source_address_prefix),
                                "source_port_range": rule.source_port_range if rule.source_port_range else "NA",
                                "destination_address_prefix": str(destination_address_prefix),
                                "destination_port_range": rule.destination_port_range if rule.destination_port_range else "NA",
                                'Timestamp': cst_time_str
                            })

                        # Check for outbound rules
                        if (rule.direction == "Outbound" and 
                            rule.access == "Allow" and 
                            rule.priority < 3600 and 
                            ("*" in source_address_prefix or "*" in destination_address_prefix)):
                            print(f"Outbound rule: {rule.name} in NSG {nsg.name} in resource group {resource_group.name} meets the criteria.")
                            results.append({
                                "SubscriptionName": sub.display_name,
                                "Subscription": sub.subscription_id,
                                "ResourceGroup": resource_group.name,
                                "NSG_Name": nsg.name,
                                "NSG_Location": nsg.location,
                                "Direction": rule.direction,
                                "Rule_Name": rule.name,
                                "source_address_prefix": str(source_address_prefix),
                                "source_port_range": rule.source_port_range if rule.source_port_range else "NA",
                                "destination_address_prefix": str(destination_address_prefix),
                                "destination_port_range": rule.destination_port_range if rule.destination_port_range else "NA",
                                'Timestamp': cst_time_str
                            })
                        logger.info(f"Found NSG rule '{rule.name}' for NSG '{nsg.name}' in resource group '{resource_group.name}' in subscription '{sub.display_name}'")
            except Exception as e:
                logger.error(f"An error occurred while processing NSGs in resource group {resource_group.name}: {e}")
                continue
    except Exception as subscription_loop_exception:
        logger.error(f"An error occurred during subscription loop: {subscription_loop_exception}")

    return results

def nsg_open_public():
    try:
        credential = DefaultAzureCredential()
        subscription_client = SubscriptionClient(credential)

        results = []
        df = pd.DataFrame(columns=["SubscriptionName", "Subscription", "ResourceGroup", "NSG_Name", "NSG_Location", "Direction", "Rule_Name", "source_address_prefix", "source_port_range", "destination_address_prefix", "destination_port_range", "Timestamp"])

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
                results.extend(executor.submit(process_nsg_rule, sub, credential).result())

        df = pd.DataFrame(results)
        table_name = 'azure_network_security_group_any_port_open_to_public'
        container_name = 'azure-network-security-group-any-port-open-to-public'
        columns = ['SubscriptionName', 'Subscription', 'ResourceGroup', 'NSG_Name', 'NSG_Location','Direction', 'Rule_Name','source_address_prefix', 'source_port_range','destination_address_prefix','destination_port_range', 'Timestamp']
        if results: 
            Azure_SQL_Convertion.SQL_function(df, table_name, columns)
            Azure_Blob_Convertion.Blob_function(df, container_name, 'main_name')
            notifications_email.send_email(container_name, container_name +' Data Report', "excel", container_name, df)

    except Exception as e:
        logger.error(f"An error occurred: {e}")

    finally:
        all_logs = csv_error_handler.get_all_logs()
        error_logs = csv_error_handler.get_error_logs()
        if all_logs:
            all_logs_df = pd.DataFrame(all_logs)
            container_name = 'azure-network-security-group-any-port-open-to-public'
            Azure_Blob_Convertion.Blob_function(all_logs_df, container_name, 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            container_name = 'azure-network-security-group-any-port-open-to-public'
            Azure_Blob_Convertion.Blob_function(error_logs_df, container_name, 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('Exception log file generated', 'azure-network-security-group-any-port-open-to-public' +' Exception Report', "excel", 'azure-network-security-group-any-port-open-to-public', error_logs_df)

# Call the function
nsg_open_public()
