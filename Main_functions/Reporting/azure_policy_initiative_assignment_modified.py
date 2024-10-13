import sys
import logging
import pandas as pd
import os
import time
from dateutil import parser
import requests
sys.path.append('.')
#sys.path.append(r'c:\program files\microsoft sdks\azure\cli2\lib\site-packages')
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from azure.identity import DefaultAzureCredential,ClientSecretCredential
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.keyvault.secrets import SecretClient
import json
import requests
from Class.Report_handler.config_param import Config
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

 # Calculate the date range for the last week
end_date = datetime.utcnow()
start_date = end_date - timedelta(days=7)
# Format the dates to the required format
start_date_str = start_date.strftime("%Y-%m-%dT%H:%M:%SZ")
end_date_str = end_date.strftime("%Y-%m-%dT%H:%M:%SZ")

# Create lists to store logs

modifications = []
credentials = DefaultAzureCredential()
subscription_client = SubscriptionClient(credentials)

keyvault_url = Config.keyvault_url
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

 # Filter the results programmatically
relevant_operations = [
            'Microsoft.Authorization/policyAssignments/write',
            'microsoft.authorization/policyassignments/write'
            'Microsoft.Authorization/policyAssignments/delete',
            'microsoft.authorization/policyassignments/delete',
            'Microsoft.Authorization/policySetDefinitions/write',
            'microsoft.authorization/policysetdefinitions/write',
            'Microsoft.Authorization/policySetDefinitions/delete',
            'microsoft.authorization/policysetdefinitions/delete',
            'Microsoft.Authorization/policyDefinitions/write',
            'microsoft.authorization/policydefinitions/write',
            'Microsoft.Authorization/policyDefinitions/delete',
            'microsoft.authorization/policydefinitions/delete',
            'Microsoft.Authorization/policyExemptions/write',
            'microsoft.authorization/policyexemptions/write',
            'Microsoft.Authorization/policyExemptions/delete',
            'microsoft.authorization/policyexemptions/delete'

        ]

# Get Token 
def get_access_token(ValueTenant, ValueCLientID, VAlueClientSecret):
    url = f'https://login.microsoftonline.com/{ValueTenant}/oauth2/v2.0/token'
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        'grant_type': 'client_credentials',
        'client_id': ValueCLientID,
        'client_secret': VAlueClientSecret,
        'scope': 'https://management.azure.com/.default'
    }
    response = requests.post(url, headers=headers, data=data)
    response.raise_for_status()
    return response.json()['access_token']

# No specific required access this SPN to get generate the Token 
access_token = get_access_token(ValueTenant, ValueCLientID, VAlueClientSecret)
#print(access_token)

#get policydetails using resourceID
def get_policy_assignment_details(resourceID):

    if "policyExemptions" in resourceID:
            api_version = "2022-07-01-preview"
    else:
            api_version = "2023-04-01"

    url = f'https://management.azure.com/{resourceID}?api-version={api_version}'
    headers = {
        'Authorization': f'Bearer {access_token}'
    } 
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        #print(response.json())
        return response.json()
    except requests.exceptions.HTTPError as http_err:
        status_code = response.status_code if response is not None else 'No response'
        print(f"HTTP error occurred: {http_err} (Status code: {status_code})")
        return {'error': 'HTTP error', 'details': str(http_err), 'status_code': status_code}
    except Exception as err:
        print(f"An error occurred: {err}")
        return {'error': 'Other error', 'details': str(err), 'status_code': 'N/A'}



# Function to extract scope and notScopes from policy assignment details
def extract_scope_and_notscopes(assignment_details):
    name = assignment_details.get('properties', {}).get('displayName', 'No name found')
    scope = assignment_details.get('properties', {}).get('scope', 'NA')
    notScopes = assignment_details.get('properties', {}).get('notScopes', 'NA')
    return {
        'name': name,
        'scope': scope,
        'notScopes': notScopes
    }
# Function to resolve SPN name using Microsoft Graph API
def resolve_spn_name(spn_id):
    #credentials1 = DefaultAzureCredential(exclude_managed_identity_credential=True)
    # Authentication
    credential = ClientSecretCredential(tenant_id=ValueTenant, client_id=ValueCLientID, client_secret=VAlueClientSecret)
    subscription_client = SubscriptionClient(credential)
    access_token = credential.get_token("https://graph.microsoft.com/.default").token
    #access_token = credentials1.get_token('https://graph.microsoft.com/.default').token
    graph_api_endpoint = f'https://graph.microsoft.com/v1.0/servicePrincipals/{spn_id}'
    headers = {
        'Authorization': 'Bearer ' + access_token,
        'Content-Type': 'application/json'
    }

    response = requests.get(graph_api_endpoint, headers=headers)

    if response.status_code == 200:
        spn_details = response.json()
        spn_name = spn_details.get('displayName', 'Unknown SPN Name')
        return spn_name
    else:
        logger.error(f"Failed to retrieve SPN details. Status code: {response.text}")
        return None
   

# Function to get all management groups
def get_management_groups():
   
    # Set up the headers with the authorization token
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    url = "https://management.azure.com/providers/Microsoft.Management/managementGroups?api-version=2021-04-01"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json().get('value', [])
    else:
        print(f"Failed to retrieve management groups. Status code: {response.status_code}")
        print(response.text)  # Print the response text for more details
        return []
# Fetch MG level activty logs    
def fetch_activity_logs_MG_level():   
    # Retrieve all management groups
    management_groups = get_management_groups()
    for mg in management_groups:
        mg_id = mg['id']
        mg_name = mg['name']
        #print(mg_id)
        
        logs = get_activity_logs(mg_id)
        if logs:
                # Filter logs based on the criteria
                filtered_logs = [
                    log for log in logs.get('value', [])
                    if log.get('resourceId', '').startswith(f'/providers/Microsoft.Management/managementGroups/{mg_name}/providers/Microsoft.Authorization')
                    and log.get('status', {}).get('localizedValue', '') == 'Succeeded'
                    and log.get('operationName', {}).get('value', '') in relevant_operations
                ]
                
                # Extract specific details from each log entry
                for log in filtered_logs:
                            #print(log)
                            assignment_details = get_policy_assignment_details(log.get('resourceId', ''))
                            if 'error' not in assignment_details:
                                    if hasattr(log, 'authorization') and log.authorization:
                                                authorization = log.authorization
                                                scope = getattr(authorization, 'scope', 'Unknown scope')
                                    result = extract_scope_and_notscopes(assignment_details)
                                    Scope = result['scope']
                                    NotScopes = result['notScopes']
                                    name = result['name'] 
                                    if NotScopes == []:
                                        NotScopes = 'NA'
                                    #print(f"Policyname-MG-->{name}")  

                                    modifications.append({
                                        #'ManagementGroup': mg_name,
                                        'Policy_Initiative_Assignment_Scope': mg_name,
                                        'Policy_Initiative_Assignment_Name': name,
                                        'AssignmentID': str(log.get('resourceId', '')),
                                        'Operation': str(log.get('operationName', {}).get('localizedValue', '')),
                                        'Change_type': str(log.get('authorization', {}).get('action', '')),
                                        'Modified_by': str(log.get('caller', '')),
                                        'lastModifiedAt': str(log.get('eventTimestamp', '')),
                                        'Assignment_Scope': str(Scope),
                                        'Excluded_scopes': str(NotScopes),
                                        'Properties': str(log.get('properties', ''))
                                    })

# Function to get activity logs for a specific management group
def get_activity_logs(management_group_id):

 try:
    headers = {
        'Authorization': 'Bearer ' + access_token,
        'Content-Type': 'application/json'
    }

    url = (f"https://management.azure.com{management_group_id}/providers/microsoft.insights/eventtypes/management/values"
           f"?api-version=2017-03-01-preview"
           f"&$filter=eventTimestamp ge '{start_date_str}' and eventTimestamp le '{end_date_str}' "
           "and eventChannels eq 'Admin, Operation' "
           "and levels eq 'Critical,Error,Warning,Informational'")

    response = requests.get(url, headers=headers)
    #print(url)
   #print(response.status_code)
    return response.json() if response.status_code == 200 else None
 except Exception as e:
        print(f"Error occurred: {e}")
        return None
   
def fetch_policy_modifications(subscription):
    try:
        #credential = DefaultAzureCredential()
        credential = ClientSecretCredential(ValueTenant, ValueCLientID, VAlueClientSecret)
        monitor_client = MonitorManagementClient(credential, subscription.subscription_id)
        # Get the last 7 days of policy assignments
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=7)

        #filtering logs only related to Policies
        resource_provider = "Microsoft.Authorization"
        filter_query = (
            f"eventTimestamp ge '{start_time.isoformat()}' and eventTimestamp le '{end_time.isoformat()}' "
            f"and resourceProvider eq '{resource_provider}'"
        )
        
        activity_logs = monitor_client.activity_logs.list(
            filter=filter_query
        )

        filtered_logs = [log for log in activity_logs if log.operation_name.value in relevant_operations]

        # iterating activity logs
        for log in filtered_logs:
            operation_name = log.operation_name.localized_value if hasattr(log.operation_name, 'localized_value') else None
            #print(operation_name)

            caller_name = log.caller
            if hasattr(log, 'authorization') and log.authorization:
                authorization = log.authorization
                action = getattr(authorization, 'action', 'Unknown Action')

            activity_status = getattr(log.status, 'value', None)
            timestamp_str = str(log.event_timestamp)
            timestamp = parser.parse(timestamp_str).replace(tzinfo=None)

            # Parse log properties
            properties = getattr(log, 'properties', {})
                       
            if properties:
                test = properties            
                response_body_str = properties.get('responseBody', '{}')
                if '@' in caller_name:  
                    initiated_by = caller_name
                elif hasattr(log, 'claims') and 'xms_mirid' in log.claims:
                    xms_mirid = log.claims['xms_mirid']
                    initiated_by = xms_mirid.rsplit('/', 1)[-1]
                else:
                    initiated_by = resolve_spn_name(caller_name)
                # Only Delete Opertions conditions checking 
                if activity_status == 'Succeeded' and operation_name in ["Delete policy assignment", "Delete policy set definition","Delete policy definition","Delete policy exemption"]:
                        resourceID = log.resource_id
                        if response_body_str:
                            response_body = json.loads(response_body_str)
                            nested_properties = response_body.get('properties', response_body)
                            resource_name = nested_properties.get('displayName', '')
                            scope = nested_properties.get('scope', '')
                            notScopes = nested_properties.get('notScopes', '')
                            if NotScopes == []:
                                NotScopes = 'NA'
                            
                            modifications.append({
                                'Policy_Initiative_Assignment_Scope': str(subscription.display_name),
                                'Policy_Initiative_Assignment_Name': str(resource_name),
                                'AssignmentID': str(resourceID),
                                'Operation': str(operation_name),
                                'Change_type': str(action),
                                'Modified_by':  str(initiated_by),
                                'lastModifiedAt':  str(timestamp),
                                'Assignment_Scope':str(scope),
                                'Excluded_scopes':str(notScopes),
                                'Properties':  str(test)
                                
                            })
                            logger.info(f"Performed operation {operation_name} type is {resource_name} in subscription {subscription.display_name}")

                 # Only Create or update Opertions conditions checking             
                elif activity_status == 'Succeeded' and operation_name in ["Create policy definition","Create policy set definition", "Create policy assignment","Create policy exemption"]:
                        resourceID = log.resource_id
                        assignment_details = get_policy_assignment_details(resourceID)
                        if 'error' not in assignment_details:
                            if hasattr(log, 'authorization') and log.authorization:
                                authorization = log.authorization
                                scope = getattr(authorization, 'scope', 'Unknown scope')
                            result = extract_scope_and_notscopes(assignment_details)
                            Scope = result['scope']
                            NotScopes = result['notScopes']
                            name = result['name']    
                            if NotScopes == []:
                                NotScopes = 'NA'
                                                  
                            modifications.append({
                                'Policy_Initiative_Assignment_Scope': str(subscription.display_name),
                                'Policy_Initiative_Assignment_Name': str(name),
                                'AssignmentID': str(resourceID),
                                'Operation': str(operation_name),
                                'Change_type': str(action),
                                'Modified_by':  str(initiated_by),
                                'lastModifiedAt':  str(timestamp),
                                'Assignment_Scope':str(Scope),
                                'Excluded_scopes': str(NotScopes),
                                'Properties':  str(test)
                                })
                            logger.info(f"Performed operation {operation_name} type is {name} in subscription {subscription.display_name}")

                                                                                                            
        return modifications

    except Exception as e:
        logger.error(f"Error occurred for subscription {subscription.subscription_id}: {e}")
        return []

# Function to list policy modifications for all subscriptions
def list_policy_modifications():
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
                logger.error(f"Invalid input subscriptions {invalid_subs}")

        with ThreadPoolExecutor() as executor:
            policy_modifications = list(executor.map(fetch_policy_modifications, subscriptions))

        #output_df = pd.DataFrame([item for sublist in policy_modifications for item in sublist])
        if modifications:
            output_df = pd.DataFrame(modifications)
            table_name = 'azure_policy_initiative_assignment_modified'
            container_name = 'azure-policy-initiative-assignment-modified'
             
            columns = ['Policy_Initiative_Assignment_Scope', 'Policy_Initiative_Assignment_Name', 'AssignmentID', 'Operation', 'Change_type', 'Modified_by', 'lastModifiedAt','Assignment_Scope', 'Excluded_scopes','Properties']
            Azure_SQL_Convertion.SQL_function(output_df, table_name, columns)
            Azure_Blob_Convertion.Blob_function(output_df, container_name, 'main_name')
            notifications_email.send_email(container_name, container_name + ' Data Report', "excel", container_name, output_df)

       
    except Exception as e:
        logger.error(f"Error occurred: {e}")
    finally:
        all_logs = csv_error_handler.get_all_logs()
        error_logs = csv_error_handler.get_error_logs()
        
        if all_logs:
            all_logs_df = pd.DataFrame(all_logs)
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-policy-initiative-assignment-modified', 'all_logs')
            logger.info("All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-policy-initiative-assignment-modified', 'error_logs')
            logger.info("Error logs generated for CSV")
            notifications_email.send_email('azure-policy-initiative-assignment-modified', 'azure-policy-initiative-assignment-modified' + ' Error Report', "excel", 'azure-policy-initiative-assignment-modified', error_logs_df)

    
fetch_activity_logs_MG_level()
list_policy_modifications()
