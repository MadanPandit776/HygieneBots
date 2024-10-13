import pandas as pd
import os
import sys
import logging
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
sys.path.append('.')
import requests
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

def get_access_token():
    """Obtain an access token using DefaultAzureCredential."""
    credential = DefaultAzureCredential()
    token = credential.get_token("https://management.azure.com/.default").token
    return token

def get_key_vault_details(subscription_id, resource_group_name, vault_name, token):
    """Fetch Key Vault details from Azure Management API."""
    url = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.KeyVault/vaults/{vault_name}?api-version=2023-02-01"
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        print(response.json())
        return response.json()

    else:
        raise Exception(f"Failed to fetch Key Vault details: {response.status_code} - {response.json()}")

def extract_retention_days(key_vault_details):
    """Extract the retention days from Key Vault details."""
    return key_vault_details.get('properties', {}).get('softDeleteRetentionInDays', 'Not enabled')

def main(subscription_id, resource_group_name, vault_name):
    """Main function to get and print Key Vault details including retention days."""
    try:
        token = get_access_token()
        key_vault_details = get_key_vault_details(subscription_id, resource_group_name, vault_name, token)
        retention_days = extract_retention_days(key_vault_details)
        print(f"Key Vault Name: {key_vault_details['name']}")
        print(f"Location: {key_vault_details['location']}")
        print(f"Retention Days: {retention_days}")
    except Exception as e:
        print(str(e))


def process_subscription(subscription):
    try:
        # Create a Key Vault client and get a list of Key Vaults
        credential = DefaultAzureCredential()
        #credential = DefaultAzureCredential(exclude_managed_identity_credential=True)
        keyvault_client = KeyVaultManagementClient(credential, subscription.subscription_id)
        keyvaults = keyvault_client.vaults.list()
        
        keyvault_soft_delete_status = []
        
        # Loop through each Key Vault
        for keyvault in keyvaults:
            keyvault_name = keyvault.name
            keyvault_id = keyvault.id
            location = keyvault.location
            resource_group = keyvault.id.split('/')[4]
            keyvault_properties = keyvault_client.vaults.get(resource_group, keyvault_name).properties
            # Check if soft delete is enabled for the Key Vault
            soft_delete_status = "Enabled" if keyvault_properties.enable_soft_delete else "Not Enabled"
            cst_time = datetime.utcnow() - timedelta(hours=6)
            cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
            main(subscription.subscription_id, resource_group, keyvault_name)
            keyvault_soft_delete_status.append({
                'SubscriptionName': subscription.display_name,
                'Subscription': subscription.subscription_id,
                'Resource_Group': resource_group,
                'Keyvault_Name': keyvault_name,
                'Keyvault_Location' : location,
                'Soft_Delete': soft_delete_status,
                'RetentionDays': str(keyvault_properties.soft_delete_retention_in_days),
                'Timestamp': cst_time_str
            })
            logger.info(f"Key vault {keyvault_name} Soft Delete Status: {soft_delete_status} in subscription {subscription.display_name} ")
        
        return keyvault_soft_delete_status
    
    except Exception as e:
        logger.error(f"An error occurred in subscription {subscription.display_name}: {e}")

def get_keyvault_soft_delete_status():
    try:
        credential = DefaultAzureCredential()
        #credential = DefaultAzureCredential(exclude_managed_identity_credential=True)
        subscription_client = SubscriptionClient(credential)
        subscriptions = subscription_client.subscriptions.list()
        user_input = sys.argv[1] if len(sys.argv) > 1 else "all" 
        
        if user_input.lower() == "all":
            subscriptions = subscription_client.subscriptions.list()
        else:
            subscription_names = [s.strip() for s in user_input.split(",")]
            subscriptions = [s for s in subscription_client.subscriptions.list() if s.display_name in subscription_names]
            valid_subs, invalid_subs = subscriptions_validations.check_valid_subscription_names(subscription_names)
            if invalid_subs:
              logger.error(f"invalid input subscriptions {invalid_subs}")
        
        keyvault_soft_delete_status = []
        
        with ThreadPoolExecutor() as executor:
            results = executor.map(process_subscription, subscriptions)
            for result in results:
                if result:
                    keyvault_soft_delete_status.extend(result)
        
        # Save results to Azure SQL and Blob Storage
        table_name = 'azure_key_vault_soft_delete_status'
        container_name = 'azure-key-vault-soft-delete-status'
        df = pd.DataFrame(keyvault_soft_delete_status)
        columns = ['SubscriptionName', 'Subscription', 'Resource_Group', 'Keyvault_Name', 'Keyvault_Location', 'Soft_Delete', 'RetentionDays','Timestamp']
        if keyvault_soft_delete_status: 
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
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-key-vault-soft-delete-status', 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-key-vault-soft-delete-status', 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('Exception log file generated', 'azure-key-vault-soft-delete-status' +' Exception Report', "excel", 'azure-key-vault-soft-delete-status', error_logs_df)



get_keyvault_soft_delete_status()
