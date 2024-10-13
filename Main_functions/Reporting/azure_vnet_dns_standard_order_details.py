import logging
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient
import pandas as pd
import sys
sys.path.append('.')
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from Class.Report_handler import Azure_SQL_Convertion, Azure_Blob_Convertion
from Class.Logging.csv_error_handler import CSVErrorHandler
from Class.Email import notifications_email
from Class.Logging import subscriptions_validations

# Initialize logging and error handling
csv_error_handler = CSVErrorHandler()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(csv_error_handler)

# DNS IPs for specified regions
DNS_IPS = {
    'southcentralus': ["172.20.216.6", "172.20.196.70", "172.28.2.198", "172.23.195.198", "172.29.128.134", "172.29.3.4"],
    'eastus': ["172.20.196.70", "172.20.216.6", "172.28.2.198", "172.23.195.198", "172.29.128.134", "172.29.3.4"],
    'germanywestcentral': ["172.23.195.198", "172.28.2.198", "172.29.128.134", "172.29.3.4", "172.20.216.6", "172.20.196.70"],
    'uksouth': ["172.28.2.198", "172.23.195.198", "172.29.128.134", "172.29.3.4", "172.20.216.6", "172.20.196.70"],
    'australiaeast': ["172.29.3.4", "172.29.128.134", "172.28.2.198", "172.23.195.198", "172.20.216.6", "172.20.196.70"],
    'southeastasia': ["172.29.128.134", "172.29.3.4", "172.28.2.198", "172.23.195.198", "172.20.216.6", "172.20.196.70"]
}

def process_subscription_vnet_dns(subscription_id, subdisplay_name, credential):
    resource_client = ResourceManagementClient(credential, subscription_id)
    network_client = NetworkManagementClient(credential, subscription_id)
    results = []

    try:
        subscription_tags = resource_client.tags.get_at_scope(f"/subscriptions/{subscription_id}")
        sub_tags = subscription_tags.properties.tags
        
        for resource_group in resource_client.resource_groups.list():
            for virtual_network in network_client.virtual_networks.list(resource_group.name):
                dns_region = virtual_network.location
                
                if dns_region not in DNS_IPS:
                    continue  # Skip regions not in the specified list

                dns_servers = virtual_network.dhcp_options.dns_servers if virtual_network.dhcp_options else None
                expected_dns_ips = DNS_IPS[dns_region]

                # Determine status
                status = "mismatch"
                if dns_servers and dns_servers == expected_dns_ips:
                    status = "OK"

                cst_time = datetime.utcnow() - timedelta(hours=6)
                cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
                output_row = {
                    "SubscriptionName": subdisplay_name,
                    "Rg_Name": resource_group.name,
                    "Vnet_Name": virtual_network.name,
                    "Vnet_Address_space": ", ".join(virtual_network.address_space.address_prefixes),
                    "Dns_Region": dns_region,
                    "Dns_Ip": ", ".join(dns_servers) if dns_servers else "N/A",
                    "Expected_Dns_Ip": ", ".join(expected_dns_ips) if expected_dns_ips else "N/A",
                    "Status": status,
                    'Timestamp': cst_time_str,
                    'Subscription_Tags': str(sub_tags) if sub_tags else "N/A",
                }
                results.append(output_row)
                logger.info(f"Virtual network '{virtual_network.name}' processed successfully in Subscription {subdisplay_name}.")

    except Exception as e:
        logger.error(f"Error processing subscription {subdisplay_name}: {e}")

    return results

def process_all_subscriptions_vnet_dns():
    credential = DefaultAzureCredential()
    subscription_client = SubscriptionClient(credential)
    user_input = sys.argv[1] if len(sys.argv) > 1 else "all"
    subscriptions = []

    try:
        if user_input.lower() == "all":
            subscriptions = list(subscription_client.subscriptions.list())
        else:
            subscription_names = [s.strip() for s in user_input.split(",")]
            subscriptions = [s for s in subscription_client.subscriptions.list() if s.display_name in subscription_names]
            valid_subs, invalid_subs = subscriptions_validations.check_valid_subscription_names(subscription_names)
            if invalid_subs:
                logger.error(f"Invalid input subscriptions: {invalid_subs}")

        all_results = []

        with ThreadPoolExecutor() as executor:
            futures = {executor.submit(process_subscription_vnet_dns, subscription.subscription_id, subscription.display_name, credential): subscription for subscription in subscriptions}
            for future in futures:
                try:
                    results = future.result()
                    all_results.extend(results)
                except Exception as e:
                    logger.error(f"Error processing future result: {e}")

        output_df = pd.DataFrame(all_results)
        table_name = 'azure_vnet_dns_standard_order_details'
        container_name = 'azure-vnet-dns-standard-order-details'
        columns = ['SubscriptionName', 'Rg_Name', 'Vnet_Name', 'Vnet_Address_space', 'Dns_Region', 'Dns_Ip', 'Expected_Dns_Ip', 'Status', 'Timestamp', 'Subscription_Tags']

        if not output_df.empty:
            Azure_SQL_Convertion.SQL_function(output_df, table_name, columns)
            Azure_Blob_Convertion.Blob_function(output_df, container_name, 'main_name')
            notifications_email.send_email(container_name, container_name + ' Data Report', "excel", container_name, output_df)

    except Exception as e:
        logger.error(f"An error occurred: {e}")
    
    finally:
        all_logs = csv_error_handler.get_all_logs()
        error_logs = csv_error_handler.get_error_logs()
        
        if all_logs:
            all_logs_df = pd.DataFrame(all_logs)
            Azure_Blob_Convertion.Blob_function(all_logs_df, container_name, 'all_logs')
            logger.info("All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, container_name, 'error_logs')
            logger.info("Error logs generated for CSV")
            notifications_email.send_email('Exception log file generated', container_name + ' Exception Report', "excel", container_name, error_logs_df)

# Entry point of the script
if __name__ == "__main__":
    process_all_subscriptions_vnet_dns()
