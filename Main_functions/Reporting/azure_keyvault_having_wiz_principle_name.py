import pandas as pd
import os
import sys
sys.path.append('.')
import logging
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.keyvault.models import AccessPolicyEntry, Permissions, KeyPermissions, SecretPermissions, CertificatePermissions
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

#Process each subscription to get Key Vault details and check SPN permissions 
def process_subscription(subscription):
    """Process each subscription to get Key Vault details and check SPN permissions."""
    try:
        credential = DefaultAzureCredential()
        keyvault_client = KeyVaultManagementClient(credential, subscription.subscription_id)
        resource_client = ResourceManagementClient(credential, subscription.subscription_id)
        subscription_tags = resource_client.tags.get_at_scope(f"/subscriptions/{subscription.subscription_id}")
        sub_tags = subscription_tags.properties.tags if subscription_tags.properties.tags else {}
 
        keyvaults = keyvault_client.vaults.list()
        keyvault_access_status = []
        # Loop every keyvaults
        for keyvault in keyvaults:
            keyvault_name = keyvault.name
            keyvault_id = keyvault.id
            resource_group = keyvault_id.split('/')[4]
            cst_time = datetime.utcnow() - timedelta(hours=6)
            cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST')
 
            try:
                # Fetch Key Vault properties
                keyvault_properties = keyvault_client.vaults.get(resource_group, keyvault_name).properties
                policies = keyvault_properties.access_policies
                wiz_spn = "no"  # Default value
               # Check polices configred or not if configured get the polices details 
                if policies:
                    for policy in policies:
                        # Check if object_id matches the specific ID
                        if policy.object_id == "37a2667c-78e4-4c4e-b12a-7ae558871d9b":
                            wiz_spn = "yes"  # Set Wiz_SPN to 'yes'
                            permissions = policy.permissions
                            # Check only 3 permissions only "secret,key,certificate"
                            secret = permissions.secrets if hasattr(permissions, 'secrets') else "None"
                            key = permissions.keys if hasattr(permissions, 'keys') else "None"
                            certificate = permissions.certificates if hasattr(permissions, 'certificates') else "None"
                            keyvault_access_status.append({
                                'SubscriptionName': subscription.display_name,
                                'SubscriptionId': subscription.subscription_id,
                                'KeyVault_RG': str(resource_group),
                                'KeyVault_Name': str(keyvault_name),
                                'Wiz_SPN': str(wiz_spn),
                                'Secret': str(secret),
                                'Key': str(key),
                                'Certificate': str(certificate),
                                'SubTAG': str(sub_tags),
                                'Timestamp': str(cst_time_str)
                            })
                            break  # No need to check further policies if object_id is found
 
                    # If the object_id is not found and RBAC is not enabled, add a new policy
                    if keyvault_properties.enable_rbac_authorization == False and wiz_spn == "no":
                        # # Define new access policy
                        # new_policy = AccessPolicyEntry(
                        #     object_id="37a2667c-78e4-4c4e-b12a-7ae558871d9b",
                        #      permissions=Permissions(
                        #         keys=[KeyPermissions.list],
                        #         secrets=[SecretPermissions.list],
                        #         certificates=[CertificatePermissions.list, CertificatePermissions.listissuers]
                        #     )
                        # )
                        # # Update Key Vault with new policy
                        # keyvault_client.vaults.begin_create_or_update(
                        #     resource_group,
                        #     keyvault_name,
                        #     properties=keyvault_properties._replace(
                        #         access_policies=policies + [new_policy]
                        #     )
                        # )
                        keyvault_access_status.append({
                            'SubscriptionName': str(subscription.display_name),
                            'SubscriptionId': str(subscription.subscription_id),
                            'KeyVault_RG': str(resource_group),
                            'KeyVault_Name': str(keyvault_name),
                            'Wiz_SPN': str(wiz_spn),
                            'Secret': "None",
                            'Key': "None",
                            'Certificate': "None",
                            'SubTAG': str(sub_tags),
                            'Timestamp': str(cst_time_str)
                        })
 
            except Exception as e:
                print(f"An error occurred processing key vault {keyvault_name}: {e}")
 
        return keyvault_access_status
    except Exception as e:
        logging.error(f"An error occurred in subscription {subscription.display_name}: {e}")
        return []
        
#Retrieve and process access policies across all subscriptions.
def get_keyvault_access_status():
    """Retrieve and process access policies across all subscriptions."""
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
 
        keyvault_access_status = []
 
        with ThreadPoolExecutor() as executor:
            results = executor.map(process_subscription, subscriptions)
            for result in results:
                if result:
                    keyvault_access_status.extend(result)
 
        df = pd.DataFrame(keyvault_access_status)
        table_name = 'azure_keyvault_having_wiz_principle_name'
        
        columns = ['SubscriptionName','SubscriptionId', 'KeyVault_RG', 'KeyVault_Name', 'Wiz_SPN','Secret', 'KeyValues', 'Certificate', 'SubTAG', 'Timestamp']
        container_name = 'azure-keyvault-having-wiz-principle-name'
        if keyvault_access_status:
            notifications_email.send_email(container_name, container_name +' Data Report', "excel", container_name, df)
            Azure_SQL_Convertion.SQL_function(df, table_name, columns)
            Azure_Blob_Convertion.Blob_function(df, container_name, 'main_name')
        
    except Exception as e:
        logging.error(f"An error occurred: {e}")
    finally:
        # Retrieve logs from the handler
        all_logs = csv_error_handler.get_all_logs()
        error_logs = csv_error_handler.get_error_logs()
        # Save all logs and error logs to Blob Storage
        if all_logs:
            all_logs_df = pd.DataFrame(all_logs)
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-keyvault-having-wiz-principle-name', 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-keyvault-having-wiz-principle-name', 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('azure-keyvault-having-wiz-principle-name', 'azure-keyvault-having-wiz-principle-name' +' Error Report', "excel", 'azure-keyvault-having-wiz-principle-name', error_logs_df)
 
 
get_keyvault_access_status()

