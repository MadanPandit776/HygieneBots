import pandas as pd
import logging
import sys
import os
import requests
sys.path.append('.')
from datetime import datetime
from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.subscription import SubscriptionClient
from collections import defaultdict
from Class.Logging.csv_error_handler import CSVErrorHandler
from Class.Report_handler import Azure_Blob_Convertion, Azure_SQL_Convertion
from Class.Email import notifications_email 

# Initialize logging and other components
csv_error_handler = CSVErrorHandler()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(csv_error_handler)

# Initialize Azure clients
credential = DefaultAzureCredential()
subscription_client = SubscriptionClient(credential)

# Caches to store resolved names
spn_cache = {}
user_cache = {}
group_cache = {}

# Function to fetch all users, groups, and service principals with pagination
def fetch_all_principals():
    base_url = "https://graph.microsoft.com/v1.0"
    endpoints = ["users", "groups", "servicePrincipals"]
    headers = {
        'Authorization': 'Bearer ' + DefaultAzureCredential(exclude_managed_identity_credential=True).get_token('https://graph.microsoft.com/.default').token,
        'Content-Type': 'application/json'
    }

    for endpoint in endpoints:
        url = f"{base_url}/{endpoint}"
        while url:
            try:
                response = requests.get(url, headers=headers)
                response.raise_for_status()  # Raise HTTPError for bad responses
                data = response.json()
                
                logger.info(f"Fetched data for {endpoint}: {data}")

                # Process each item based on the endpoint
                for item in data.get('value', []):
                    if endpoint == 'users':
                        user_cache[item['id']] = item['displayName']
                    elif endpoint == 'groups':
                        group_cache[item['id']] = item['displayName']
                    elif endpoint == 'servicePrincipals':
                        spn_cache[item['id']] = item['displayName']

                # Check for pagination
                url = data.get('@odata.nextLink')
            except requests.RequestException as e:
                logger.error(f"Failed to retrieve {endpoint}. Error: {e}")
                break

# Function to resolve SPN name using the cached data
def resolve_spn_name(principal_id, principal_type):
    print(principal_type)
    if principal_type == "user":
        return user_cache.get(principal_id, "Unknown User Name")
    elif principal_type == "group":
        return group_cache.get(principal_id, "Unknown Group Name")
    elif principal_type == "serviceprincipal":
        return spn_cache.get(principal_id, "Unknown SPN Name")
    else:
        return "Unknown Principal Type"

# Function to get role assignments for a subscription
def get_role_assignments_for_subscription(subscription_id):
    auth_client = AuthorizationManagementClient(credential, subscription_id)
    role_assignments = []
    try:
        for assignment in auth_client.role_assignments.list_for_scope(f"/subscriptions/{subscription_id}"):
            role_assignments.append(assignment)
    except Exception as e:
        logger.error(f"Error retrieving role assignments for subscription {subscription_id}: {e}")
    return role_assignments

# Function to fetch role definitions for a subscription
def fetch_role_definitions(subscription_id):
    auth_client = AuthorizationManagementClient(credential, subscription_id)
    role_definitions = {}
    try:
        for role_def in auth_client.role_definitions.list(f"/subscriptions/{subscription_id}"):
            role_definitions[role_def.id] = role_def.role_name
    except Exception as e:
        logger.error(f"Error retrieving role definitions for subscription {subscription_id}: {e}")
    return role_definitions

# Function to process a role assignment
def process_role_assignment(subscription_id, subscription_name, assignment, role_definitions, role_data):
    try:
        scope = assignment.scope
        scope_parts = scope.split("/")

        # Determine the scope level and other relevant details
        scope_level, management_group, resource_group, resource = "", "", "", ""
        if "providers" in scope_parts and "Microsoft.Management" in scope_parts:
            scope_level = "ManagementGroup"
            management_group = scope_parts[4]
        elif "subscriptions" in scope_parts:
            if "resourceGroups" in scope_parts or "resourcegroups" in [part.lower() for part in scope_parts]:
                resource_group_index = scope_parts.index("resourceGroups") if "resourceGroups" in scope_parts else [part.lower() for part in scope_parts].index("resourcegroups")
                resource_group = scope_parts[resource_group_index + 1]
                if len(scope_parts) == resource_group_index + 2:
                    scope_level = "ResourceGroup"
                else:
                    scope_level = "Resource"
                    resource = "/".join(scope_parts[resource_group_index + 2:])
            else:
                scope_level = "Subscription"
        else:
            scope_level = "ROOT"

        # Collect role assignment details
        object_id = assignment.principal_id
        role_definition_id = assignment.role_definition_id
        role_assignment_id = assignment.id
        role_type = "Direct"
        role_name = role_definitions.get(role_definition_id, "Unknown")
        principal_type = assignment.principal_type.lower() if assignment.principal_type else "unknown"
        principal_type = "servicePrincipal" if "SPN" in assignment.principal_type else principal_type
        principal_name = resolve_spn_name(object_id, principal_type)

        logger.debug(f"Resolved name for {principal_type} with ID {object_id}: {principal_name}")

        # Add role assignment details to the role data dictionary
        role_data[(object_id, role_definition_id, scope_level, management_group, subscription_name, resource_group, resource)].append({
            "ScopeLevel": scope_level,
            "ManagementGroup": management_group,
            "SubscriptionName": subscription_name,
            "ResourceGroup": resource_group,
            "Resource": resource,
            "ObjectType": "ServicePrincipal" if "SPN" in assignment.principal_type else assignment.principal_type,
            "ObjectName": principal_name,
            "ObjectId": object_id,
            "Status": "Unique",
            "RoleDefinitionId": role_definition_id,
            "RoleDefinitionName": role_name,
            "RoleAssignmentId": role_assignment_id,
            "Scope": scope,
            "SubscriptionID": subscription_id,
        })
        logger.info(f"Processed role assignment for subscription {subscription_name}")

    except Exception as e:
        logger.error(f"Error processing role assignment for subscription {subscription_name}: {e}")

# Main function to process all role assignments
def main():
    try:
        subscriptions = []
        try:
            subscriptions = list(subscription_client.subscriptions.list())
        except Exception as e:
            logger.error(f"Error retrieving subscriptions: {e}")

        role_definitions_cache = {}
        role_data = defaultdict(list)

        # Fetch all principals
        fetch_all_principals()

        for sub in subscriptions:
            subscription_id = sub.subscription_id
            subscription_name = sub.display_name

            # Fetch role definitions once per subscription
            role_definitions = fetch_role_definitions(subscription_id)
            role_definitions_cache[subscription_id] = role_definitions

            # Fetch role assignments for the subscription and process each assignment
            role_assignments = get_role_assignments_for_subscription(subscription_id)
            for assignment in role_assignments:
                process_role_assignment(subscription_id, subscription_name, assignment, role_definitions, role_data)

        # Determine duplicates and set status
        level_order = {"ManagementGroup": 1, "Subscription": 2, "ResourceGroup": 3, "Resource": 4}
        all_roles = defaultdict(list)
        
        for key, roles in role_data.items():
            if len(roles) > 1:
                roles.sort(key=lambda r: level_order.get(r["ScopeLevel"], 5))
                roles[0]["Status"] = "Retained"
                for role in roles[1:]:
                    role["Status"] = "Can be removed"
            all_roles[(key[0], key[1])].extend(roles)

        # Additional check for duplicates across different scope levels
        for (object_id, role_definition_id), roles in all_roles.items():
            if len(roles) > 1:
                roles.sort(key=lambda r: level_order.get(r["ScopeLevel"], 5))
                higher_level_role = roles[0]
                for role in roles[1:]:
                    if role["ScopeLevel"] != higher_level_role["ScopeLevel"]:
                        if role["ScopeLevel"] == "Resource" and higher_level_role["ScopeLevel"] == "ResourceGroup":
                            role["Status"] = "Unique"
                        else:
                            role["Status"] = "Can be removed"
                        higher_level_role["Status"] = "Retained"

        # Convert role data to a DataFrame
        rows = []
        for key, roles in role_data.items():
            rows.extend(roles)

        # Filter out unique records
        filtered_rows = [row for row in rows if row['Status'] != 'Unique']
        df = pd.DataFrame(filtered_rows)
        
        container_name = 'azure-rbac-duplicate-access-details'
        table_name = 'azure_rbac_duplicate_access_details'        
        columns = ['ScopeLevel', 'ManagementGroup', 'SubscriptionName', 'ResourceGroup', 'Resource', 'ObjectType', 'ObjectName','ObjectId', 'Status', 'RoleDefinitionId', 'RoleDefinitionName', 'RoleAssignmentId','Scope','SubscriptionID']
        Azure_Blob_Convertion.Blob_function(df, container_name, 'main_name')
        Azure_SQL_Convertion.sql_convertion(df, table_name, columns)
        notifications_email.send_email(container_name, container_name + ' Data Report', "excel", container_name, df)

    except Exception as e:
        logger.error(f"Error in main function: {e}")
    finally:
        # Retrieve logs from the handler
        all_logs = csv_error_handler.get_all_logs()
        error_logs = csv_error_handler.get_error_logs()
        # Save all logs and error logs to Blob Storage
        if all_logs:
            all_logs_df = pd.DataFrame(all_logs)
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-rbac-duplicate-access-details', 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-rbac-duplicate-access-details', 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('Exception log file generated', 'azure-rbac-duplicate-access-details'+' Exception Report',"excel", 'azure-rbac-duplicate-access-details', error_logs_df)


if __name__ == "__main__":
    main()
