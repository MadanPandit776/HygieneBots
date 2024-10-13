import logging
import pandas as pd
import os
import sys
sys.path.append('.')
from datetime import datetime, timedelta
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.resource import SubscriptionClient
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
 

def process_subscription(subscription, credential):
    created_dns_zones = []
    
    try:
        subscription_name = subscription.display_name
        subscription_id = subscription.subscription_id
        resource_client = ResourceManagementClient(credential, subscription.subscription_id)
        subscription_tags = resource_client.tags.get_at_scope(f"/subscriptions/{subscription_id}")
        sub_tags = subscription_tags.properties.tags
        # Get List of privateDnsZones under every Resource Group
        for rg in resource_client.resource_groups.list():
            resources = resource_client.resources.list_by_resource_group(rg.name, filter="resourceType eq 'Microsoft.Network/privateDnsZones'")
            # Get details of every privateDnsZones 
            for resource in resources:
                dns_zone_name = resource.name
                resource_group = resource.id.split('/')[4]
               
                cst_time = datetime.utcnow() - timedelta(hours=6)
                cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
                # Check if the DNS zone was created both outside the specific subscription and resource group
                if not resource_group.startswith("pep-network") and not "isolated" in resource_group:
                    created_dns_zones.append({
                        'SubscriptionName': subscription_name,
                        'SubscriptionID': subscription_id,
                        'Resource_Group': resource_group,
                        'Private_DNS_Zone_Name': str(dns_zone_name),
                        'Sub_Tag': str(sub_tags) if sub_tags else "N/A",
                        'Timestamp': str(cst_time_str),
                    })
                    logger.info(f" Private DNS Zone without standard RG {resource_group} in subscription {subscription_name}")
        return created_dns_zones
    except Exception as e:
        logger.error(f"Error occurred for subscription {subscription.subscription_id}: {e}")
        return []
 
def list_created_dns_zones():
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
 
        created_dns_zones = []

        with ThreadPoolExecutor() as executor:
            results = executor.map(lambda sub: process_subscription(sub, credential), subscriptions)

            for result in results:
                created_dns_zones.extend(result)

       
 
        df = pd.DataFrame(created_dns_zones)
        table_name = 'azure_private_dns_zone_without_standard_resource_group'
        columns = ['SubscriptionName','SubscriptionID', 'Resource_Group', 'Private_DNS_Zone_Name', 'Sub_Tag', 'Timestamp']
        container_name = 'azure-private-dns-zone-without-standard-resource-group'
        if created_dns_zones:
            notifications_email.send_email(container_name, container_name +' Data Report', "excel", container_name, df)
            Azure_SQL_Convertion.SQL_function(df, table_name, columns)
            Azure_Blob_Convertion.Blob_function(df, container_name, 'main_name')
 
        
    except Exception as e:
        logger.error(f"Error occurred: {e}")
    finally:
        # Retrieve logs from the handler
        all_logs = csv_error_handler.get_all_logs()
        error_logs = csv_error_handler.get_error_logs()
        # Save all logs and error logs to Blob Storage
        if all_logs:
            all_logs_df = pd.DataFrame(all_logs)
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-private-dns-zone-without-standard-resource-group', 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-private-dns-zone-without-standard-resource-group', 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('azure-private-dns-zone-without-standard-resource-group', 'azure-private-dns-zone-without-standard-resource-group' +' Error Report', "excel", 'azure-private-dns-zone-without-standard-resource-group', error_logs_df)

 
if __name__ == "__main__":
    list_created_dns_zones()

 