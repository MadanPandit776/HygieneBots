import pandas as pd
import logging
import os
import sys
sys.path.append('.')
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource.subscriptions import SubscriptionClient
from azure.mgmt.resource import ResourceManagementClient
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
 
# Keywords to search in NSG names
KEYWORDS = ["business", "frontend", "backend"]
 
# List of common rules with their priorities
COMMON_RULES = {
    "ib_pepinternal_all_rdp_temp": 3501,
    "ib_rubrik": 3502,
    "ib_pepinternal_all_ping_temp": 3503,
    "ib_ad_dc_to_member_servers": 3504,
    "ib_powerbroker": 3505,
    "ib_bigfix": 3506,
    "ib_nimsoft_tcp": 3507,
    "ib_nimsoft_udp": 3508,
    "ib_tripwire": 3509,
    "ib_qualys": 3510,
    "ib_mycloudssh": 3511,
    "ib_builddnd": 3512,
    "ib_buildnfs": 3513,
    "ib_servicenowdiscovery": 3514,
    "ib_qualys_infosec": 3515,
    "ib_cr_mypam": 3516,
    "ib_cr_servicenowdiscovery_udp": 3517,
    "ib_cr_linux_patching": 3518,
    "ib_cr_win_patching": 3519,
    "ib_cr_ekcm_cert_mgt": 3520,
    "ib_cr_fortify": 3521,
    "ib_cmp_ansible": 3535,
    "ib_azure_LB": 4095,
    "ib_deny_all": 4096,
    "ob_tanium": 3501,
    "ob_rubrik": 3502,
    "ob_pepinternal_all_ping_temp": 3503,
    "ob_member_servers_to_dc": 3504,
    "ob_powerbroker": 3505,
    "ob_bigfix": 3506,
    "ob_nimsoft_tcp": 3507,
    "ob_nimsoft_udp": 3508,
    "ob_tripwire": 3509,
    "ob_qualys": 3510,
    "ob_mycloud": 3511,
    "ob_builddnd": 3512,
    "ob_buildnfs": 3513,
    "ob_proxy": 3514,
    "ob_dns": 3515,
    "ob_rhuirepo": 3516,
    "ob_linux_license": 3517,
    "ob_symantec": 3518,
    "ob_ntp": 3519,
    "ob_slesrepo": 3520,
    "ob_sles_smt_onprem": 3521,
    "ob_bigfix_icmp": 3522,
    "ob_cr_internet": 3523,
    "ob_cr_okta": 3524,
    "ob_cr_tanium_taas": 3525,
    "ob_cr_azure_gtm": 3526,
    "ob_cr_idx_lb": 3527,
    "ob_cr_elkmonitoring": 3528,
    "ob_azurekms": 3529,
    "ob_cmp_ansible": 3535,
    "ob_paas_storage": 4091,
    "ob_azureactivedirectory": 4092,
    "ob_azuresiterecovery": 4093,
    "ob_pass_eventhub": 4094,
    "ob_azure_LB": 4095,
    "ob_deny_all": 4096,
    "ob_cr_oracleoid": 3901,
    "ob_cr_oracleoem12c": 3902,
    "ob_cr_oracleoem13c": 3903,
    "ob_cr_oraclewebsvc": 3904,
    "ob_cr_oracledbr": 3905,
    "ob_cr_observer": 3906,
    "ob_cr_sqldbr_migration": 3907,
    "ob_cr_guardium": 3908,
    "ob_cr_zenoss": 3909,
    "ob_cr_zenoss_udp": 3910
}
 
# Initialize Azure credential
credential = DefaultAzureCredential()
subscription_client = SubscriptionClient(credential)
results = []
 
def check_nsgs(subscription):
    subscription_name = subscription.display_name
    subscription_id = subscription.subscription_id
    network_client = NetworkManagementClient(credential, subscription_id)
    resource_client = ResourceManagementClient(credential, subscription_id)
    subscription_tags = resource_client.tags.get_at_scope(f"/subscriptions/{subscription_id}")
    sub_tags = subscription_tags.properties.tags
    try:
        # List all Network Security Groups in the subscription
        nsgs = network_client.network_security_groups.list_all()
        for nsg in nsgs:
            cst_time = datetime.utcnow() - timedelta(hours=6)
            cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
            if any(keyword.lower() in nsg.name.lower() for keyword in KEYWORDS):
                # Get NSG rules
                rules = network_client.security_rules.list(nsg.id.split('/')[4], nsg.name)
                existing_rules = {rule.name: rule.priority for rule in rules}
                missing_rules = {rule_name: COMMON_RULES[rule_name] for rule_name in COMMON_RULES if rule_name not in existing_rules}
                # If any common rules are missing, add NSG to the results
                if missing_rules:
                    missing_rules_str = ", ".join([f"{rule_name} (Priority: {priority})" for rule_name, priority in missing_rules.items()])
                    results.append({
                        "Subscription": subscription_name,
                        "Subscription_ID": subscription_id,
                        "NSG_name": nsg.name,
                        "NSG_RG": nsg.id.split('/')[4],
                        "Missing_Rules": missing_rules_str,  
                        'Sub_Tag': str(sub_tags) if sub_tags else "N/A",
                        'Timestamp': str(cst_time_str)
                    })
                    print(f"NSG {nsg.name} does not have common NSG rules: {missing_rules_str}")
    except Exception as e:
        logging.error(f"Error processing subscription {subscription_id}: {e}")
 
def main():
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
        # Use ThreadPoolExecutor for parallel execution
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(check_nsgs, sub): sub for sub in subscriptions}
            for future in as_completed(futures):
                subscription = futures[future]
                try:
                    future.result()
                except Exception as e:
                    logging.error(f"Error processing subscription {subscription.subscription_id}: {e}")
        # Create a DataFrame
        df = pd.DataFrame(results)
        table_name = 'azure_nsg_without_common_security_groups'
        columns = ['Subscription','Subscription_ID', 'NSG_name', 'NSG_RG','Missing_Rules', 'Sub_Tag', 'Timestamp']
        container_name = 'azure-nsg-without-common-security-groups'
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
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-nsg-without-common-security-groups', 'all_logs')
        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-nsg-without-common-security-groups', 'error_logs')
 
if __name__ == '__main__':
    main()

