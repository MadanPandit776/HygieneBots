import logging
import os
import sys
import pandas as pd
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.network.models import SecurityRule
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
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
        subscription_id = subscription.subscription_id
        subscription_name = subscription.display_name

        network_client = NetworkManagementClient(credential, subscription_id)
        nsgs = network_client.network_security_groups.list_all()

        nsg_details = []

        for nsg in nsgs:
            nsg_id = nsg.id
            nsg_name = nsg.name
            nsg_location = nsg.location
            nsg_rules = network_client.security_rules.list(resource_group_name=nsg_id.split('/')[4], network_security_group_name=nsg_name)

            for rule in nsg_rules:
                if rule.direction == "Inbound" and rule.access == "Allow" and rule.destination_port_range == "21" and rule.source_address_prefix == "*" and rule.destination_address_prefix == "*":
                    cst_time = datetime.utcnow() - timedelta(hours=6)
                    cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
                    print(nsg_name)
                    # Disable FTP port open to public
                    credentials = DefaultAzureCredential(exclude_managed_identity_credential=True)
                    network_clients = NetworkManagementClient(credentials, subscription_id)
                    
                    #-------------------- Remidation Block Start-----------------------------------------------------------------
                    rule.access = "Deny"
                    updated_rule = network_clients.security_rules.begin_create_or_update(
                        resource_group_name=nsg_id.split('/')[4],
                        network_security_group_name=nsg_name,
                        security_rule_name=rule.name,
                        security_rule_parameters=rule
                    )
                    #-------------------- Remidation Block END-----------------------------------------------------------------
         
                    nsg_details.append({
                        'SubscriptionName': str(subscription_name),
                        'Subscription': str(subscription_id),
                        'NSG_Name': str(nsg_name),
                        'NSG_ID': str(nsg_id),
                        'NSGRuleName': str(rule.name),
                        'Rule_Direction': str(rule.direction),
                        'Rule_access': str(rule.access),
                        'Source_Address_Prefix': str(rule.source_address_prefix),
                        'Destination_Address_Prefix': str(rule.destination_address_prefix),
                        'NSG_Location': str(nsg_location),
                        'Destination_Port': str(rule.destination_port_range),
                        'Timestamp': str(cst_time_str)
                    })
                    logger.info(f"Found Health status for {nsg_name} in subscription {subscription_name}")

        return nsg_details

    except Exception as e:
        logger.error(f"An error occurred during subscription {subscription.display_name} processing: {e}")
        return []

def deny_public_access_to_ftp_ports():
    try:
        #credential = DefaultAzureCredential(exclude_managed_identity_credential=True)
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

        nsg_details = []

        with ThreadPoolExecutor() as executor:
            results = executor.map(lambda sub: process_subscription(sub, credential), subscriptions)
            for result in results:
                nsg_details.extend(result)

        df = pd.DataFrame(nsg_details)
        # Save results to Azure SQL and Blob Storage
        table_name = 'azure_network_security_group_ftp_port_open_to_public'
        container_name = 'azure-network-security-group-ftp-port-open-to-public'
        columns = ['SubscriptionName', 'Subscription', 'NSG_Name', 'NSG_ID', 'NSGRuleName', 'Rule_Direction','Rule_access','Source_Address_Prefix','Destination_Address_Prefix','NSG_Location','Destination_Port', 'Timestamp']
        if nsg_details: 
         Azure_SQL_Convertion.SQL_function(df, table_name, columns)
         Azure_Blob_Convertion.Blob_function(df, container_name, 'main_name')
         notifications_email.send_email(container_name, container_name +' Data Report', "excel", container_name, df)

    except Exception as e:
        logger.error(f"An error occurred: {e}")
    finally:
        # Retrieve logs from the handler
        all_logs = csv_error_handler.get_all_logs()
        error_logs = csv_error_handler.get_error_logs()
        # Save all logs and error logs to Blob Storage
        if all_logs:
            all_logs_df = pd.DataFrame(all_logs)
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-network-security-group-ftp-port-open-to-public', 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-network-security-group-ftp-port-open-to-public', 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('Exception log file generated', 'azure-network-security-group-ftp-port-open-to-public' +' Exception Report', "excel", 'azure-network-security-group-ftp-port-open-to-public', error_logs_df)


deny_public_access_to_ftp_ports()
