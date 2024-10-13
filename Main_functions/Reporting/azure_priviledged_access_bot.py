import logging
import os
import sys
sys.path.append('.')
import pandas as pd
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient
from datetime import datetime
import requests
from Class.Email import notifications_email
from Class.Report_handler import Azure_SQL_Convertion, Azure_Blob_Convertion
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

# Initialize Azure clients
credential = DefaultAzureCredential()
subscription_client = SubscriptionClient(credential)

# Exclusion list
excluded_subscriptions = ["pep-testing-01-sub", "pep-dr-testing-01-sub", "pep-sandbox-01-sub"]

# Define exclusion lists below format

    # "subscrption_ID": {
    #     "Object_ID": "Object_Name",
    # }
# Exclude principal types follwing by subscription id 

exclusion_ids_by_subscription = {

    "be5a74ea-b1dc-4662-963c-15f6d9d714f7": {
        "8335743c-6055-4ca1-871e-caafbde7d6bb": "Team.Support.SPDev.Admins",
    },
    "0e6f0d5a-ca39-44c4-9013-9a9350dd7afe": {
        "592d6a95-0b5c-41f1-abe7-d135636d7f23": "PepsiCo One-Touch"
    },
    "0f2cbc50-d58f-4d61-81fe-ee0af2f71b23": {
        "592d6a95-0b5c-41f1-abe7-d135636d7f23": "PepsiCo One-Touch"
    },
    "287a5b24-6a3b-4eac-a045-8be37098fc53": {
        "fb692ddb-4595-4a3b-817a-3c73ac696858": "SEN_COG_OWNER_ACCESS"
    },
    "2ab35e30-575a-4335-b901-3b9009286220": {
        "fb692ddb-4595-4a3b-817a-3c73ac696858": "SEN_COG_OWNER_ACCESS"
    },
    "302b39fa-635b-4cff-9963-b855b7ff85cd": {
        "d287419f-670e-4de2-b39a-32f683829701": "Role.Support.Azure.Admins"
    },
    "68e42618-47ec-45f4-9377-6021803e4fad": {
        "dd1abeef-b1ae-472c-aad7-1104473d6547": "Team.Support.eCommerce.Admins"
    },
    "68e769a9-138e-4f56-b005-f95e1fc0f76b": {
        "9f31e51f-27aa-4910-acc1-8d380a1b67c3": "Service SvcAPPMSCRM"
    },
    "6c7b9e3f-09a7-434c-afb6-739351dfa7c6": {
        "ccb11dd2-881d-45c9-b971-b9df09ddc747": "Team.Support.Azure.VDIEngineering"
    },
    "80306051-70ac-4ae0-95c7-5e797ba30a9c":{
        "dd1abeef-b1ae-472c-aad7-1104473d6547": "Team.Support.eCommerce.Admins"
    },
    "891018c6-3380-4d46-8dca-4a63b715ee3c":{
        "d287419f-670e-4de2-b39a-32f683829701": "Role.Support.Azure.Admins"
    },
    "a77cd6dd-9302-4410-881a-0450821d9b27":{
        "592d6a95-0b5c-41f1-abe7-d135636d7f23": "PepsiCo One-Touch"
    },
    "c8b8ae0e-7715-4a7e-a6ac-b435952a6062":{
        "fb692ddb-4595-4a3b-817a-3c73ac696858": "SEN_COG_OWNER_ACCESS"
    },
    "cc5a1ece-543d-459a-a2d1-58c487fac7c2":{
        "a6c94ffa-9c11-4090-a613-e7ffdc75d113": "Team.Support.GDA.Admins"
    },
    "d6451cb5-7d7a-4caf-84e2-5fbaa36c083e":{
        "147ecb33-0119-4fe1-8493-179590fd9d12": "pep-testing-01-sub", 
        "d084db29-6411-462a-ac2a-5db8ffb43ae0": "Gong, George xu {PEP}", 
        "2eeb1ab1-4dfa-4490-9386-dc4224b01f14": "Nath, Birojit {PEP}",
        "f6ac70e8-f85a-42a3-b974-9ba299906a8e": "Gowen, Richard {PEP}", 
        "8e4d000d-fbdc-4084-aa27-ffc2b5507d76": "Birlea, Nicolae {PEP}",
        "4cf792ea-f555-40d9-9931-0509a62b6330": "Team.Support.ArchEng" 
    },
    "ee31cabe-6ef3-414f-823a-fa7659d65575":{
        "9f31e51f-27aa-4910-acc1-8d380a1b67c3": "Service SvcAPPMSCRM"
    },
    "f5b22329-e7c7-45c6-ae23-3ad399f007d1":{
        "42ffd763-3e95-4ebb-8bac-0fb9a4facec1": "ZertoPBNADRUAMI"
    },
    "feb87e96-6e72-4613-8c2f-5285d9b68587":{
        "c0b4e99d-a5af-4ff6-ac5e-c2071dda6a2f": "Team.App.TechScouting.Owner"
    }
}

# Function to resolve SPN name using Microsoft Graph API
def resolve_principal_name(principal_id, principal_type):
    base_url = "https://graph.microsoft.com/v1.0"
    headers = {
        'Authorization': 'Bearer ' + DefaultAzureCredential(exclude_managed_identity_credential=True).get_token('https://graph.microsoft.com/.default').token,
        'Content-Type': 'application/json'
    }

    endpoint = ""
    if principal_type.lower() == "user":
        endpoint = "users"
    elif principal_type.lower() == "group":
        endpoint = "groups"
    elif principal_type.lower() == "serviceprincipal":
        endpoint = "servicePrincipals"
    else:
        return "Unknown Principal Type"

    url = f"{base_url}/{endpoint}/{principal_id}"

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise HTTPError for bad responses
        data = response.json()

        display_name = data.get('displayName', "Unknown Display Name")
        return display_name

    except requests.RequestException as e:
        print(f"Failed to retrieve {principal_type} with ID {principal_id}. Error: {e}")
        return f"Error retrieving name for {principal_id}"

# Get Role Assignments of that subscription
def get_role_assignments_for_subscription(subscription_id):
    auth_client = AuthorizationManagementClient(credential, subscription_id)
    role_assignments = []
    try:
        for assignment in auth_client.role_assignments.list_for_scope(scope=f"/subscriptions/{subscription_id}"):
            role_assignments.append(assignment)
    except Exception as e:
        logger.error(f"Error retrieving role assignments for subscription {subscription_id}: {e}")
    return role_assignments

# Get Role Definations
def fetch_role_definitions(subscription_id):
    auth_client = AuthorizationManagementClient(credential, subscription_id)
    role_definitions = {}
    try:
        for role_def in auth_client.role_definitions.list(f"/subscriptions/{subscription_id}"):
            role_definitions[role_def.id] = role_def.role_name
    except Exception as e:
        logger.error(f"Error retrieving role definitions for subscription {subscription_id}: {e}")
    return role_definitions

# Get Subscription Tags
def get_subscription_tags(subscription_id):
    tags = {}
    try:
        resource_client = ResourceManagementClient(credential, subscription_id)
        tag_info = resource_client.tags.get_at_scope(f"/subscriptions/{subscription_id}")
        tags = tag_info.properties.tags
    except Exception as e:
        logger.error(f"Error retrieving tags for subscription {subscription_id}: {e}")
    return tags

def process_role_assignment(subscription_id, subscription_name, assignment, role_data, role_definitions):
    try:
            scope = assignment.scope
            object_id = assignment.principal_id
            role_definition_id = assignment.role_definition_id
            role_name = role_definitions.get(role_definition_id, "Unknown")
        
        # Check if the role is "Owner"
        #if role_name.lower() == "owner":
            principal_type = assignment.principal_type.lower() if assignment.principal_type else "unknown"
            principal_type = "servicePrincipal" if "spn" in principal_type else principal_type
        
            # Determine the scope level and extract relevant information
            # Example of scope parts (this would be obtained from splitting the scope URL)
            scope_parts = scope.lower().strip('/').split('/')
            if f"/subscriptions/{subscription_id}/resourcegroups/" in scope.lower():
                # Resource Group or Resource Level
                resource_group_index = scope_parts.index("resourcegroups") if "resourcegroups" in scope_parts else None
                if resource_group_index is not None:
                    resource_group_name = scope_parts[resource_group_index + 1]
                    subscription_tags = get_subscription_tags(subscription_id)
                    if len(scope_parts) == resource_group_index + 2:
                    # Resource Group Level - Check only "Owner" roles
                     if role_name.lower() == "owner":
                        principal_name = resolve_principal_name(object_id, principal_type)
                        # Resource Group Level
                        role_data.append({
                            "SubscriptionName": subscription_name,
                            "PrincipalType": principal_type,
                            'PrincipalName': str(principal_name),
                            'scope_level': "ResourceGroup",
                            'role_name': role_name,
                            "Scope": resource_group_name,
                            "Sub_Tag": str(subscription_tags)
                        })
                        logger.info(f"Owner role found: {principal_name} at the resource group level in subscription {subscription_name}, Resource Group {resource_group_name}")
                    else:
                    # Resource Level - Check only "Owner" roles
                       if role_name.lower() == "owner":
                        principal_name = resolve_principal_name(object_id, principal_type)
                        # Resource Level
                        resource_name = "/".join(scope_parts[resource_group_index + 2:])
                        role_data.append({
                            "SubscriptionName": subscription_name,
                            "PrincipalType": principal_type,
                            'PrincipalName': str(principal_name),
                            'scope_level': "Resource",
                            'role_name': role_name,
                            "Scope": resource_name,
                            "Sub_Tag": str(subscription_tags)
                        })
                        logger.info(f"Owner role found: {principal_name} at the resource level in subscription {subscription_name}, Resource Group {resource_group_name}, Resource {resource_name}")

            elif f"/subscriptions/{subscription_id}" == scope.lower():
                # Subscription Level
                # Subscription Level - Check both "Owner" and "Contributor" roles
             if role_name.lower() in ["owner", "contributor"]:
                principal_name = resolve_principal_name(object_id, principal_type)
                subscription_tags = get_subscription_tags(subscription_id)
                if subscription_id in exclusion_ids_by_subscription:
                    if object_id in exclusion_ids_by_subscription[subscription_id]:
                        return
                role_data.append({
                    "SubscriptionName": subscription_name,
                    "PrincipalType": principal_type,
                    'PrincipalName': str(principal_name),
                    'scope_level': "Subscription",
                    'role_name': role_name,
                    "Scope": subscription_name,
                    "Sub_Tag": str(subscription_tags)
                })
                logger.info(f"Owner role found: {principal_name} at the subscription level in subscription {subscription_name}")

    except Exception as e:
            logger.error(f"Error processing role assignment for subscription {subscription_name}: {e}")


def main():
    try:
        role_data = []

        user_input = ' '.join(sys.argv[1:]) if len(sys.argv) > 1 else "all"
        if user_input.lower() == "all":
            subscriptions = subscription_client.subscriptions.list()
        else:
            subscription_names = [s.strip() for s in user_input.split(",")]
            subscriptions = [s for s in subscription_client.subscriptions.list() if s.display_name in subscription_names]
            valid_subs, invalid_subs = subscriptions_validations.check_valid_subscription_names(subscription_names)
            if invalid_subs:
                logger.error(f"invalid input subscriptions {invalid_subs}")

        for sub in subscriptions:
            subscription_name = "Unknown Subscription"
            subscription_id = sub.subscription_id
            try:
                sub = subscription_client.subscriptions.get(subscription_id)
                subscription_name = sub.display_name
            except Exception as e:
                logger.error(f"Error retrieving subscription {subscription_id}: {e}")
            # Exclude mentioned subscrtiptions above array list
            if subscription_name in excluded_subscriptions:
             continue

            role_definitions = fetch_role_definitions(subscription_id)
            role_assignments = get_role_assignments_for_subscription(subscription_id)

            for assignment in role_assignments:
                process_role_assignment(subscription_id, subscription_name, assignment,role_data,role_definitions)

        df = pd.DataFrame(role_data)
        if role_data:
            columns = ['SubscriptionName', 'PrincipalType', 'PrincipalName','scope_level','role_name', 'Scope','Sub_Tag']
            container_name = 'azure-priviledged-access-bot'
            table_name = 'azure_priviledged_access_bot'
            Azure_SQL_Convertion.SQL_function(df, table_name, columns)
            Azure_Blob_Convertion.Blob_function(df, container_name, 'main_name')
            notifications_email.send_email(container_name, container_name + ' Data Report', "excel", container_name, df)

    except Exception as e:
        logger.error(f"Error in main function: {e}")
    finally:
        all_logs = csv_error_handler.get_all_logs()
        error_logs = csv_error_handler.get_error_logs()
        if all_logs:
            all_logs_df = pd.DataFrame(all_logs)
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-priviledged-access-bot', 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-priviledged-access-bot', 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('azure-priviledged-access-bot', 'azure-priviledged-access-bot' + ' Error Report', "excel", 'azure-priviledged-access-bot', error_logs_df)

main()
