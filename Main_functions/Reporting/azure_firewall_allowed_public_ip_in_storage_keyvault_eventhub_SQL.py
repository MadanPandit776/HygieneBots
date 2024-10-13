import logging
import os
import sys
from azure.identity import DefaultAzureCredential
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.eventhub import EventHubManagementClient
sys.path.append('.')
import pandas as pd
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from Class.Report_handler import Azure_SQL_Convertion
from Class.Report_handler import Azure_Blob_Convertion
from Class.Logging.csv_error_handler import CSVErrorHandler
from Class.Email import notifications_email
from Class.Logging import subscriptions_validations
import ipaddress

# Create lists to store logs
all_logs = []
error_logs = []

# Instantiate the handler
csv_error_handler = CSVErrorHandler()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(csv_error_handler)

# # Define standard IP ranges
standard_ip_ranges = [
    "165.197.220.224 - 165.197.220.255",
    "165.197.181.224 - 165.197.181.255",
    "165.197.73.224 - 165.197.73.255",
    "165.197.216.224 - 165.197.216.225",
    "165.197.64.224 - 165.197.64.255"
]

# Define standard CIDR ranges
required_ip_ranges = [
    "165.197.64.224/27",
    "165.197.220.224/27",
    "165.197.73.224/27",
    "165.197.216.224/27",
    "165.197.181.224/27"
]

def check_required_ip_ranges(firewall_ranges):
    for range in required_ip_ranges:
        if range not in firewall_ranges:
            return False
    return True



def check_required_ip_ranges_sql(firewall_ranges):
    firewall_ranges_list = [range.strip() for range in firewall_ranges.split(', ')]

    def parse_ip_range(ip_range_str):
        start_ip, end_ip = ip_range_str.split(' - ')
        return ipaddress.ip_address(start_ip), ipaddress.ip_address(end_ip)

    firewall_ip_ranges = [parse_ip_range(range_str) for range_str in firewall_ranges_list]
    
    # Log the parsed firewall IP ranges
    print(f"Parsed firewall IP ranges: {firewall_ip_ranges}")

    for required_range in standard_ip_ranges:
        required_start_ip, required_end_ip = parse_ip_range(required_range)
        found = any(start_ip <= required_start_ip and end_ip >= required_end_ip for start_ip, end_ip in firewall_ip_ranges)
        if not found:
            print(f"Missing required range: {required_range}")
            return False
    return True




# def check_required_ip_ranges_sql(firewall_ranges):
#     for range in standard_ip_ranges:
#         if range not in firewall_ranges:
#             return False
#     return True

def process_storage(storage, subscription_name, resources, credential):
    storage_name = storage.name
    storage_id = storage.id
    resource_group = storage.id.split('/')[4]
    location = storage.location
    cst_time = datetime.utcnow() - timedelta(hours=6)
    cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
    try:
        network_rules = storage.network_rule_set
        firewall_rules = network_rules.ip_rules
        firewall_ranges = ', '.join(rule.ip_address_or_range for rule in firewall_rules) if firewall_rules else "No firewall rules"
        
        has_required_ranges = check_required_ip_ranges(firewall_ranges)
        resource_status = "Yes" if has_required_ranges else "No"

        resources.append({
            'SubscriptionName': subscription_name, 
            'ResourceGroup': resource_group, 
            'Resource_Name': storage_name,
            'ResourceType': 'Storage Account', 
            'ResourceId': storage_id,
            'Resource_Location': location,
            'Firewall_Range': firewall_ranges,
            'Timestamp': cst_time_str,
            'Ranges_Configured': resource_status
        })
        logger.info(f"Found firewall rules for storage account {storage_name} in subscription {subscription_name}")
    except Exception as e:
        logger.error(f"Failed to get firewall rules for storage account {storage_name} in subscription {subscription_name}: {e}")

# Helper function to process key vaults
def process_key_vault(vault, subscription_name, resources, credential, keyvault_client):
    vault_name = vault.name
    vault_id = vault.id
    vault_location = vault.location
    resource_group = vault_id.split('/')[4]
    cst_time = datetime.utcnow() - timedelta(hours=6)
    cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
    try:
        properties = keyvault_client.vaults.get(resource_group, vault_name)
        network_rule_set = properties.properties.network_acls
        firewall_rules = network_rule_set.ip_rules
        firewall_ranges = ', '.join(rule.value for rule in firewall_rules) if firewall_rules else "No firewall rules"
        
        has_required_ranges = check_required_ip_ranges(firewall_ranges)
        resource_status = "Yes" if has_required_ranges else "No"

        resources.append({
            'SubscriptionName': subscription_name, 
            'ResourceGroup': resource_group, 
            'Resource_Name': vault_name,
            'ResourceType': 'Key Vault',
            'ResourceId': vault_id,
            'Resource_Location': vault_location,
            'Firewall_Range': firewall_ranges,
            'Timestamp': cst_time_str,
            'Ranges_Configured': resource_status
        })
        logger.info(f"Found firewall rules for key vault {vault_name} in subscription {subscription_name}")
    except Exception as e:
        logger.error(f"Failed to get firewall rules for key vault {vault_name} in subscription {subscription_name}: {e}")

# Helper function to process SQL servers
def process_sql_server(sql_server, subscription_name, resources, credential, sql_client):
    resource_group = sql_server.id.split('/')[4]
    sql_server_name = sql_server.name
    location = sql_server.location
    cst_time = datetime.utcnow() - timedelta(hours=6)
    cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')

    try:
        firewall_ranges = []
        for rule in sql_client.firewall_rules.list_by_server(resource_group, sql_server_name):
            start_ip = rule.start_ip_address.strip()
            end_ip = rule.end_ip_address.strip()
            firewall_ranges.append(f"{start_ip} - {end_ip}")
        firewall_ranges_str = ', '.join(firewall_ranges) if firewall_ranges else "No firewall rules"
        
        # Log the constructed firewall ranges string
        print(f"Constructed firewall ranges string: {firewall_ranges_str}")
        
        has_required_ranges = check_required_ip_ranges_sql(firewall_ranges_str)
        resource_statuss = "Yes" if has_required_ranges else "No"

        resources.append({
            'SubscriptionName': subscription_name, 
            'ResourceGroup': resource_group, 
            'Resource_Name': sql_server_name,
            'ResourceType': 'SQL Server', 
            'ResourceId': sql_server.id,
            'Resource_Location': location,
            'Firewall_Range': firewall_ranges_str,
            'Timestamp': cst_time_str,
            'Ranges_Configured': resource_statuss
        })
        logger.info(f"Found firewall rules for SQL server {sql_server_name} in subscription {subscription_name}")
    except Exception as e:
        logger.error(f"Failed to get firewall rules for SQL server {sql_server_name} in subscription {subscription_name}: {e}")

# Helper function to process event hubs
def process_event_hub(namespace, subscription_name, resources, credential, eventhub_client):
    namespace_name = namespace.name
    namespace_id = namespace.id
    namespace_location = namespace.location
    resource_group = namespace_id.split('/')[4]
    cst_time = datetime.utcnow() - timedelta(hours=6)
    cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
    try:
        properties = eventhub_client.namespaces.get_network_rule_set(resource_group, namespace_name)
        firewall_rules = properties.ip_rules
        firewall_ranges = ', '.join(rule.ip_mask for rule in firewall_rules) if firewall_rules else "No firewall rules"
    
        has_required_ranges = check_required_ip_ranges(firewall_ranges)
        resource_status = "Yes" if has_required_ranges else "No"
        resources.append({
            'SubscriptionName': subscription_name, 
            'ResourceGroup': resource_group,
            'Resource_Name': namespace_name,
            'ResourceType': 'Event Hub',
            'ResourceId': namespace_id,
            'Resource_Location': namespace_location,
            'Firewall_Range': firewall_ranges,
            'Timestamp': cst_time_str,
            'Ranges_Configured': resource_status
        })
        logger.info(f"Found firewall rules for event hub namespace {namespace_name} in subscription {subscription_name}")
    except Exception as e:
        logger.error(f"Failed to get firewall rules for event hub namespace {namespace_name} in subscription {subscription_name}: {e}")

def process_subscription(subscription, credential):
    resources = []
    try:
        subscription_id = subscription.subscription_id
        subscription_name = subscription.display_name

        # Check Storage Accounts
        storage_client = StorageManagementClient(credential, subscription_id)
        for storage in storage_client.storage_accounts.list():
            # Process storage accounts concurrently
            process_storage(storage, subscription_name, resources, credential)

        # Check Key Vaults
        keyvault_client = KeyVaultManagementClient(credential, subscription_id)
        for vault in keyvault_client.vaults.list():
            # Process key vaults concurrently
            process_key_vault(vault, subscription_name, resources, credential, keyvault_client)

        # Check Azure SQL databases
        sql_client = SqlManagementClient(credential, subscription_id)
        for sql_server in sql_client.servers.list():
            # Process SQL servers concurrently
            process_sql_server(sql_server, subscription_name, resources, credential, sql_client)

        # Check Event Hubs
        eventhub_client = EventHubManagementClient(credential, subscription_id)
        for namespace in eventhub_client.namespaces.list():
            # Process event hubs concurrently
            process_event_hub(namespace, subscription_name, resources, credential, eventhub_client)

    except Exception as e:
        logger.error(f"Failed to process resources for subscription {subscription.display_name}: {e}")
    
    return resources

def main():
    credential = DefaultAzureCredential()
    subscription_client = SubscriptionClient(credential)
    all_resources = []
    user_input = sys.argv[1] if len(sys.argv) > 1 else "all"
        # Get subscriptions based on user input
    if user_input.lower() == "all":
            subscriptions = subscription_client.subscriptions.list()
    else:
            # Get the subscriptions that match the user input
            subscription_names = [s.strip() for s in user_input.split(",")]
            subscriptions = subscription_client.subscriptions.list()
            subscriptions = [s for s in subscriptions if s.display_name in subscription_names]
            valid_subs, invalid_subs = subscriptions_validations.check_valid_subscription_names(subscription_names)
            if invalid_subs:
              logger.error(f"invalid input subscriptions {invalid_subs}")
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(process_subscription, subscription, credential) for subscription in subscriptions]
        for future in futures:
            try:
                resources = future.result()
                all_resources.extend(resources)
            except Exception as e:
                logger.error(f"An error occurred: {e}")

    if all_resources:
        table_name = 'azure_firewall_allowed_public_ip_in_storage_keyvault_eventhub_SQL'
        container_name = 'azure-firewall-public-ip-storage-keyvault-eventhub-sql'
        columns = ['SubscriptionName', 'ResourceGroup', 'Resource_Name', 'ResourceType', 'ResourceId', 'Resource_Location', 'Firewall_Range', 'Timestamp', 'Ranges_Configured']
        df = pd.DataFrame(all_resources)
        Azure_SQL_Convertion.SQL_function(df, table_name, columns)
        Azure_Blob_Convertion.Blob_function(df, container_name, 'main_name')
        notifications_email.send_email(container_name, container_name + ' Data Report', "excel", container_name, df)
 
    if all_logs:
        all_logs_df = pd.DataFrame(all_logs)
        container_name = 'azure-firewall-public-ip-storage-keyvault-eventhub-sql'
        Azure_Blob_Convertion.Blob_function(all_logs_df, container_name, 'all_logs')
        logger.info(f"All logs generated for CSV")
 
    if error_logs:
        error_logs_df = pd.DataFrame(error_logs)
        container_name = 'azure-firewall-public-ip-storage-keyvault-eventhub-sql'
        Azure_Blob_Convertion.Blob_function(error_logs_df, container_name, 'error_logs')
        logger.info(f"Error logs generated for CSV")
        notifications_email.send_email('Exception log file generated', 'azure-firewall-public-ip-storage-keyvault-eventhub-sql' + 'Exception Report', "excel", 'azure-firewall-public-ip-storage-keyvault-eventhub-sql', error_logs_df)
 


if __name__ == '__main__':
    main()
