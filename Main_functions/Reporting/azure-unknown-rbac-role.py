import os
import pandas as pd
import requests
import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
sys.path.append('.')
from azure.identity import DefaultAzureCredential
from azure.identity import ClientSecretCredential
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.authorization import AuthorizationManagementClient
from datetime import datetime
from Class.Email import notifications_email
from azure.keyvault.secrets import SecretClient
from Class.Report_handler import Azure_SQL_Convertion
from Class.Report_handler import Azure_Blob_Convertion
from Class.Logging.csv_error_handler import CSVErrorHandler
from Class.Logging import subscriptions_validations
from Class.Report_handler.config_param import Config

# Create lists to store logs
all_logs = []
error_logs = []

# Instantiate the handler
csv_error_handler = CSVErrorHandler()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(csv_error_handler)

# Azure credentials and tenant information
keyvault_url = Config.keyvault_url
credentials = DefaultAzureCredential()
secret_client = SecretClient(vault_url=keyvault_url, credential=credentials)

Tenant = Config.Tenant_ID
CLientID = Config.Client_ID
ClientSecret = Config.Client_Secret

GetTenant = secret_client.get_secret(Tenant)
GetCLientID = secret_client.get_secret(CLientID)
GetClientSecret = secret_client.get_secret(ClientSecret)

ValueTenant = GetTenant.value
ValueCLientID = GetCLientID.value
VAlueClientSecret = GetClientSecret.value

# Authentication
credential = ClientSecretCredential(tenant_id=ValueTenant, client_id=ValueCLientID, client_secret=VAlueClientSecret)
subscription_client = SubscriptionClient(credential)
token = credential.get_token("https://graph.microsoft.com/.default").token

# REST API headers
headers = {
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json"
}

# Object type and initialization of results
OBJTYPE = "Unknown"
report_data = []

# List of subscription names to process
subscription_list = ["pep-sandbox-01-sub"]  # Replace with actual subscription names

# Get the Name of principal type
def get_principal_name(principal_id):
    endpoints = [
        f"https://graph.microsoft.com/v1.0/users/{principal_id}",
        f"https://graph.microsoft.com/v1.0/groups/{principal_id}",
        f"https://graph.microsoft.com/v1.0/servicePrincipals/{principal_id}"
    ]
    
    for endpoint in endpoints:
        try:
            response = requests.get(endpoint, headers=headers)
            if response.status_code == 200:
                return response.json().get('displayName', 'Unknown')
        except Exception as e:
            logger.error(f"Error fetching principal name for ID {principal_id} from {endpoint}: {str(e)}")
    
    return "Unknown"

def process_subscription(subscription_name):
    try:
        # Select subscription
        subscription = next(s for s in subscription_client.subscriptions.list() if s.display_name == subscription_name)
        sub_scope_path = f"/subscriptions/{subscription.subscription_id}"
        print(sub_scope_path)
        
        # Authorization client for role assignments
        auth_client = AuthorizationManagementClient(credential, subscription.subscription_id)
        
        # Fetch all role definitions
        role_definitions = list(auth_client.role_definitions.list(scope=sub_scope_path))
        role_definition_dict = {rd.id: rd.role_name for rd in role_definitions}

        # Fetch role assignments
        role_assignments = list(auth_client.role_assignments.list_for_scope(sub_scope_path))
        
        for role in role_assignments:
            role_name = role_definition_dict.get(role.role_definition_id, "Unknown Role")
            print(role_name)
            principal_name = get_principal_name(role.principal_id)
            print(principal_name)

            # Filter only the roles where principal name is "Unknown"
            if principal_name == "Unknown":
                role_data = {
                    "ScopeLevel": "",
                    "ObjectType": str(role.principal_type) or "Unknown",
                    "ObjectId": str(role.principal_id) or "Unknown",
                    "RoleDefinitionName":str(role_name),
                    "Scope": str(role.scope),
                    "DisplayName": str(principal_name)
                }

                # # Determine ScopeLevel and ResourceGroup/Resource
                # if role.scope == sub_scope_path:
                #     if subscription_name:
                #        role_data["ScopeLevel"] = "Subscription"
                #     else:
                #         role_data["ScopeLevel"] = "ManagementGroup"
                # elif (f"{sub_scope_path}/resourceGroups/" in role.scope or f"{sub_scope_path}/resourcegroups/" in role.scope) and "/providers/" in role.scope:
                #     role_data["ScopeLevel"] = "Resource"
                #     role_data["ResourceGroup"] = role.scope.split('/')[4]
                #     role_data["Resource"] = role.scope.split('providers/')[-1]
                # elif f"{sub_scope_path}/resourceGroups/" in role.scope or f"{sub_scope_path}/resourcegroups/" in role.scope:
                #     role_data["ScopeLevel"] = "ResourceGroup"
                #     role_data["ResourceGroup"] = role.scope.split('/')[4]
                # else:
                #     role_data["ScopeLevel"] = "Other"
                #     role_data["Resource"] = role.scope

                # Determine ScopeLevel and ResourceGroup/Resource
                if role.scope == sub_scope_path:
                    if subscription_name:
                        role_data["ScopeLevel"] = "Subscription"
                    else:
                        role_data["ScopeLevel"] = "ManagementGroup"
                        
                    # Set ResourceGroup and Resource to "NA" if empty
                    role_data["ResourceGroup"] = "NA"
                    role_data["Resource"] = "NA"
                    
                elif (f"{sub_scope_path}/resourceGroups/" in role.scope or f"{sub_scope_path}/resourcegroups/" in role.scope) and "/providers/" in role.scope:
                    role_data["ScopeLevel"] = "Resource"
                    role_data["ResourceGroup"] = role.scope.split('/')[4]
                    role_data["Resource"] = role.scope.split('providers/')[-1]
                    
                elif f"{sub_scope_path}/resourceGroups/" in role.scope or f"{sub_scope_path}/resourcegroups/" in role.scope:
                    role_data["ScopeLevel"] = "ResourceGroup"
                    role_data["ResourceGroup"] = role.scope.split('/')[4]
                    
                else:
                    role_data["ScopeLevel"] = "Other"
                    role_data["Resource"] = role.scope

                # Ensure ResourceGroup and Resource are "NA" if they were not set above
                if "ResourceGroup" not in role_data:
                    role_data["ResourceGroup"] = "NA"
                if "Resource" not in role_data:
                    role_data["Resource"] = "NA"

                
                report_data.append(role_data)
                
                logger.info(f"Unknown RBAC found at scope: {role.scope}")
    except Exception as e:
        logger.error(f"An error occurred while processing subscription {subscription_name}: {str(e)}")

def main():
    try:
        user_input = sys.argv[1] if len(sys.argv) > 1 else "all"
        if user_input.lower() == "all":
            subscriptions = subscription_client.subscriptions.list()
        else:
            subscription_names = [s.strip() for s in user_input.split(",")]
            subscriptions = [s for s in subscription_client.subscriptions.list() if s.display_name in subscription_names]
            valid_subs, invalid_subs = subscriptions_validations.check_valid_subscription_names(subscription_names)
            if invalid_subs:
                logger.error(f"Invalid subscription names: {', '.join(invalid_subs)}")

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(process_subscription, sub.display_name): sub.display_name for sub in subscriptions}
            for future in as_completed(futures):
                sub_name = futures[future]
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Error processing subscription {sub_name}: {str(e)}")

        df = pd.DataFrame(report_data)
        table_name = 'azure_unknown_rbac_role'
        columns = ['ScopeLevel','ObjectType','ObjectId','RoleDefinitionName','Scope','DisplayName','ResourceGroup','Resource']
        container_name = 'azure-unknown-rbac-role'
        if report_data:
            notifications_email.send_email(container_name, container_name + ' Data Report', "excel", container_name, df)
            Azure_SQL_Convertion.SQL_function(df, table_name, columns)
            Azure_Blob_Convertion.Blob_function(df, container_name, 'main_name')
    except Exception as e:
        logger.error(f"Error occurred during subscription processing: {e}")
    finally:
        # Retrieve logs from the handler
        all_logs = csv_error_handler.get_all_logs()
        error_logs = csv_error_handler.get_error_logs()
        # Save all logs and error logs to Blob Storage
        if all_logs:
            all_logs_df = pd.DataFrame(all_logs)
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-unknown-rbac', 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-unknown-rbac', 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('azure-unknown-rbac', 'azure-unknown-rbac' + ' Error Report', "excel", 'azure-unknown-rbac', error_logs_df)

if __name__ == "__main__":
    main()
