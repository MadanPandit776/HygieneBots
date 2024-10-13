import logging
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.network import NetworkManagementClient
import pandas as pd
from azure.mgmt.resource import SubscriptionClient
from azure.identity import DefaultAzureCredential
import sys
import requests
sys.path.append('.')
import os
from datetime import datetime, timedelta
from dateutil import parser
from azure.mgmt.monitor import MonitorManagementClient
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
 

# Define updated NSG rules
all_nsg_rules_v38 = [
    "ib_pepinternal_all_rdp_temp", "ib_rubrik", "ib_pepinternal_all_ping_temp",
    "ib_ad_dc_to_member_servers", "ib_powerbroker", "ib_bigfix",
    "ib_nimsoft_tcp", "ib_nimsoft_udp", "ib_tripwire", "ib_qualys",
    "ib_mycloudssh", "ib_builddnd", "ib_buildnfs", "ib_servicenowdiscovery",
    "ib_qualys_infosec", "ib_cr_mypam", "ib_cr_servicenowdiscovery_udp",
    "ib_cr_linux_patching", "ib_cr_win_patching", "ib_cr_ekcm_cert_mgt",
    "ib_cr_fortify", "ib_cmp_ansible", "ib_azure_LB", "ib_deny_all",
    "ob_tanium", "ob_rubrik", "ob_pepinternal_all_ping_temp",
    "ob_member_servers_to_dc", "ob_powerbroker", "ob_bigfix",
    "ob_nimsoft_tcp", "ob_nimsoft_udp", "ob_tripwire", "ob_qualys",
    "ob_mycloud", "ob_builddnd", "ob_buildnfs", "ob_proxy", "ob_dns",
    "ob_rhuirepo", "ob_linux_license", "ob_symantec", "ob_ntp",
    "ob_slesrepo", "ob_sles_smt_onprem", "ob_bigfix_icmp", "ob_cr_internet",
    "ob_cr_okta", "ob_cr_tanium_taas", "ob_cr_azure_gtm", "ob_cr_idx_lb",
    "ob_cr_elkmonitoring", "ob_azurekms", "ob_cmp_ansible",
    "ob_paas_storage", "ob_azureactivedirectory", "ob_azuresiterecovery",
    "ob_pass_eventhub", "ob_azure_LB", "ob_deny_all"
]
 
db_nsg_rules_v38 = [
    "ib_cr_oracleoem12c", "ib_cr_oracleoem13c", "ib_cr_oraclewebsvc",
    "ib_cr_oracleobserver", "ib_cr_sqldbr_sync", "ib_cr_sqldbr_migration",
    "ib_cr_guardium", "ib_cr_zenoss_tcp", "ib_cr_zenoss_udp", "ib_cr_ayehu",
    "ob_cr_oracleoid", "ob_cr_oracleoem12c", "ob_cr_oracleoem13c",
    "ob_cr_oraclewebsvc", "ob_cr_oracledbr", "ob_cr_observer",
    "ob_cr_sqldbr_migration", "ob_cr_guardium", "ob_cr_zenoss",
    "ob_cr_zenoss_udp"
]
def resolve_spn_name(spn_id):
    credentials1 = DefaultAzureCredential(exclude_managed_identity_credential=True)
    access_token = credentials1.get_token('https://graph.microsoft.com/.default').token
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

# Function to process each subscription
def process_subscription(sub, credential):
    results = []
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=7)
    try:
        subscription_id = sub.subscription_id
        subscription_name = sub.display_name
        resource_client = ResourceManagementClient(credential, subscription_id)
        subscription_tags = resource_client.tags.get_at_scope(f"/subscriptions/{subscription_id}")
        sub_tags = subscription_tags.properties.tags
        network_client = NetworkManagementClient(credential, subscription_id)
        monitor_client = MonitorManagementClient(credential, subscription_id)
        nsgs = network_client.network_security_groups.list_all()
        # Check every NSG details
        for nsg in nsgs:
            nsg_name = nsg.name
            nsg_rg = nsg.id.split('/')[4]
            nsg_rules = nsg.security_rules
           
            # Query activity logs for NSG rule modifications
            activity_logs = monitor_client.activity_logs.list(
                filter=f"eventTimestamp ge '{start_time.isoformat()}' and eventTimestamp le '{end_time.isoformat()}' and resourceUri eq '{nsg.id}'",
                select='eventTimestamp,caller,operationName,properties,status,resourceId'
            )
            print({start_time.isoformat()})
            print({end_time.isoformat()})
            #for rule in nsg_rules:
            for log in activity_logs:
                operation_name = log.operation_name.localized_value if hasattr(log.operation_name, 'localized_value') else None
                activity_status = getattr(log.status, 'value', None)
                caller_name = log.caller
                timestamp_str = str(log.event_timestamp)
                timestamp = parser.parse(timestamp_str).replace(tzinfo=None)
                cst_time = datetime.utcnow() - timedelta(hours=6)
                cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
                rule_id = log.resource_id
                rule_name = rule_id.split('/')[-1]
                print(rule_name)
                
                #if rule_name in all_nsg_rules_v38 or rule_name in db_nsg_rules_v38:
                #for rule in nsg_rules:
                #if (rule_name in all_nsg_rules_v38 or rule_name in db_nsg_rules_v38) and operation_name in ['Create or Update Security Rule', 'Delete Security Rule'] and activity_status == 'Succeeded' and rule.priority > 3500:
                # Check conditions like if rule should be in array list and operation should be either delete or create rule and status shouls be Succeeded
                if (rule_name in all_nsg_rules_v38 or rule_name in db_nsg_rules_v38) and operation_name in ['Create or Update Security Rule', 'Delete Security Rule'] and activity_status == 'Succeeded':
                        if '@' in caller_name:  # Check if it's an email address
                                        initiated_by = caller_name  # Use email directly
                        elif hasattr(log, 'claims') and 'xms_mirid' in log.claims:
                                        xms_mirid = log.claims['xms_mirid']
                                        initiated_by = xms_mirid.rsplit('/', 1)[-1]
                        else:
                                        initiated_by = resolve_spn_name(caller_name)
                        results.append({
                            "SubscriptionName": subscription_name,
                            "Subscription_ID": subscription_id,
                            "ResourceGroup": nsg_rg,
                            "NSG_Name": nsg_name,
                            'OperationPerformed': str(operation_name),
                            'NSGRuleName': rule_name,
                            #'PriorityNumber': str(rule.priority),
                            'ChangeMadeOn': str(timestamp),
                            'WhoPerformed': initiated_by,
                            'Sub_Tag': str(sub_tags) if sub_tags else "N/A",
                            'Timestamp': str(cst_time_str)
                        })
                        logger.info(f"Found NSG change '{operation_name}' made by '{caller_name}' for NSG '{nsg_name}' in resource group '{nsg_rg}' in subscription '{subscription_name}'")
    except Exception as subscription_loop_exception:
        logger.error(f"An error occurred during subscription loop: {subscription_loop_exception}")
 
    return results
 
def track_nsg_changes():
    try:
        credential = DefaultAzureCredential()
        subscription_client = SubscriptionClient(credential)
        results = []
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
                # Process each subscription concurrently
                results.extend(executor.submit(process_subscription, sub, credential).result())

        # Convert the results to a DataFrame
        df = pd.DataFrame(results)
        table_name = 'azure_nsg_common_rule_modification_activity'
        columns = ['SubscriptionName','Subscription_ID', 'ResourceGroup', 'NSG_Name', 'OperationPerformed', 'NSGRuleName',  'ChangeMadeOn', 'WhoPerformed', 'Sub_Tag', 'Timestamp']
        container_name = 'azure-nsg-common-rule-modification-activity'
        if results:
            notifications_email.send_email(container_name, container_name +' Data Report', "excel", container_name, df)
            Azure_SQL_Convertion.SQL_function(df, table_name, columns)
            Azure_Blob_Convertion.Blob_function(df, container_name, 'main_name')
                
    except Exception as e:
        logger.error(f"An error occurred: {e}")
    finally:
        # Retrieve logs from the handler
        all_logs = csv_error_handler.get_all_logs()
        error_logs = csv_error_handler.get_error_logs()
        # Save all logs and error logs to Blob Storage
        if all_logs:
            all_logs_df = pd.DataFrame(all_logs)
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-nsg-common-rule-modification-activity', 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-nsg-common-rule-modification-activity', 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('azure-nsg-common-rule-modification-activity', 'azure-nsg-common-rule-modification-activity' +' Error Report', "excel", 'azure-nsg-common-rule-modification-activity', error_logs_df)
 
# Call the function
track_nsg_changes()
