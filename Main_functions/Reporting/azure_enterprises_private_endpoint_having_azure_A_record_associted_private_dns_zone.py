import logging
import pandas as pd
import sys
sys.path.append('.')
import requests
import os
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.privatedns import PrivateDnsManagementClient
from azure.core.exceptions import ResourceNotFoundError
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

# Azure authentication and client initialization
credentials = DefaultAzureCredential()
subscription_client = SubscriptionClient(credentials)

def resolve_SPN_name(sub_id, rg_name, private_endpoint_name):
    try:
        dns_zone_ids = []

        # Get access token using DefaultAzureCredential
        token_credential = DefaultAzureCredential()
        token = token_credential.get_token("https://management.azure.com/.default").token

        # Construct the private DNS zone API URL
        private_dns_zone = f'https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{rg_name}/providers/Microsoft.Network/privateEndpoints/{private_endpoint_name}/privateDnsZoneGroups?api-version=2021-05-01'

        # HTTP request headers
        headers = {
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json'
        }

        # Make the GET request to fetch private DNS zone details
        response = requests.get(private_dns_zone, headers=headers)
        response.raise_for_status()  # Raise an exception for 4xx/5xx status codes

        # Process the response JSON
        spn_details = response.json()
        for entry in spn_details.get('value', []):
            private_dns_configs = entry.get('properties', {}).get('privateDnsZoneConfigs', [])
            for config in private_dns_configs:
                private_dns_zone_id = config.get('properties', {}).get('privateDnsZoneId')
                if private_dns_zone_id:
                    dns_zone_ids.append(private_dns_zone_id)

        return dns_zone_ids

    except Exception as e:
        logger.error(f"Failed to resolve SPN name: {e}")
        return None

def process_subscription(subscription):
    try:
        subscription_id = subscription.subscription_id
        subscription_name = subscription.display_name

        # Initialize clients
        resource_client = ResourceManagementClient(credentials, subscription_id)
        subscription_tags = resource_client.tags.get_at_scope(f"/subscriptions/{subscription_id}")
        sub_tags = subscription_tags.properties.tags
        network_client = NetworkManagementClient(credentials, subscription_id)

        results = []

        # Retrieve resource groups
        resource_groups = resource_client.resource_groups.list()
        for resource_group in resource_groups:
            resource_group_name = resource_group.name

            try:
                # Retrieve private endpoints in the resource group
                private_endpoints = network_client.private_endpoints.list(resource_group_name)

                for private_endpoint in private_endpoints:
                    cst_time = datetime.utcnow() - timedelta(hours=6)
                    cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST')

                    try:
                     private_endpoint_name = private_endpoint.name  
                     if private_endpoint.private_link_service_connections:
                      private_link_connection_state = private_endpoint.private_link_service_connections[0].private_link_service_connection_state.status 
                     else:
                      private_link_connection_state = private_endpoint.manual_private_link_service_connections[0].private_link_service_connection_state.status 
                      
                     #private_link_connection_state = private_endpoint.private_link_service_connections[0].private_link_service_connection_state.status if private_endpoint.private_link_service_connections else "Unknown"

                    # Determine the private IP address of the endpoint
                     private_ip_address = None
                     for nic in private_endpoint.network_interfaces:
                        network_interface = network_client.network_interfaces.get(resource_group_name, nic.id.split('/')[-1])
                        if network_interface.ip_configurations:
                            for ip_config in network_interface.ip_configurations:
                             private_ip_address = ip_config.private_ip_address
                             #private_ip_address = network_interface.ip_configurations[0].private_ip_address
                            # Check if start with "172."
                             if private_ip_address and private_ip_address.startswith("172."):
                                    dns_zone_details = resolve_SPN_name(subscription_id, resource_group_name, private_endpoint.name)
                                    # Extract DNS zone details
                                    dns_zone_name = None
                                    dns_zone_sub_name = None
                                    dns_zone_rg = None
                                    a_record_in_pdns = "No"
                                    dns_resolution = "No"
                                    # Check only Zone details
                                    if dns_zone_details:
                                        dns_resolution = "Yes"
                                        for zonedetail in dns_zone_details:
                                            print(zonedetail)
                                            dns_zone_name = zonedetail.split('/')[-1]
                                            dns_zone_sub_name = subscription_client.subscriptions.get(zonedetail.split('/')[2]).display_name
                                            dns_zone_rg = zonedetail.split('/')[4]
                                            dns_client = PrivateDnsManagementClient(credentials, zonedetail.split('/')[2])                                            

                                            record_sets = dns_client.record_sets.list(dns_zone_rg, dns_zone_name)
                                            #Check if private endpoint IP and DNS zone IP are same then its having A record
                                            for record_set in record_sets:
                                                if record_set.a_records:
                                                    for a_record in record_set.a_records:
                                                        if private_ip_address and a_record.ipv4_address == private_ip_address:
                                                            a_record_in_pdns = "Yes"

                                            results.append({
                                                "SubscriptionName": subscription_name,
                                                "SubscriptionID": str(subscription_id),
                                                "ResourceGroup": str(resource_group_name),
                                                "PrivateEndpointName": str(private_endpoint_name),
                                                "PrivateDNSZone": str(dns_zone_name) if dns_zone_details else "NA",
                                                "DNS_configuration": str(dns_resolution),
                                                "ConnectionState": str(private_link_connection_state),
                                                "PrivateDNSZone_Sub": str(dns_zone_sub_name),
                                                "PrivateDNSZone_RG": str(dns_zone_rg),
                                                "IP": str(private_ip_address),
                                                "A_record_status": str(a_record_in_pdns),
                                                "Sub_Tag": str(sub_tags) if sub_tags else "N/A",
                                                "Timestamp": str(cst_time_str)
                                            })
                                            logger.info(f"Private endpoint having A record {private_endpoint_name} in subscription {subscription_name}")
                    except ResourceNotFoundError as e:
                     logger.error(f"Error subscription {subscription.display_name} processing: {e}")
            except ResourceNotFoundError as e:
               logger.error(f"An error occurred during subscription {subscription.display_name} processing: {e}")

        return results

    except Exception as e:
        logger.error(f"Failed to process subscription {subscription.display_name}: {e}")
        return []

def main():
    try:
        # Get user input for choice of subscriptions
        user_input = sys.argv[1] if len(sys.argv) > 1 else "all"

        if user_input.lower() == "all":
            subscriptions = subscription_client.subscriptions.list()
        else:
            subscription_names = [s.strip() for s in user_input.split(",")]
            subscriptions = [s for s in subscription_client.subscriptions.list() if s.display_name in subscription_names]
            valid_subs, invalid_subs = subscriptions_validations.check_valid_subscription_names(subscription_names)
            if invalid_subs:
                logger.error(f"invalid input subscriptions {invalid_subs}")

        # Process subscriptions in parallel
        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(process_subscription, subscription) for subscription in subscriptions]

            # Collect results from completed futures
            all_results = []
            for future in as_completed(futures):
                try:
                    results = future.result()
                    all_results.extend(results)
                except Exception as e:
                    logger.error(f"Error processing subscription: {e}")

        # Convert results to DataFrame
        df = pd.DataFrame(all_results)
        
        table_name = 'azure_enterprises_pe_a_record_associted_private_dns_zone'
        columns = ['SubscriptionName','SubscriptionID', 'ResourceGroup', 'PrivateEndpointName', 'PrivateDNSZone', 'DNS_configuration','ConnectionState','PrivateDNSZone_Sub','PrivateDNSZone_RG', 'IP', 'A_record_status', 'Sub_Tag', 'Timestamp']
        container_name = 'azure-enterprises-pe-a-record-associted-private-dns-zone'
        if all_results:
            notifications_email.send_email(container_name, container_name +' Data Report', "excel", container_name, df)
            Azure_SQL_Convertion.SQL_function(df, table_name, columns)
            Azure_Blob_Convertion.Blob_function(df, container_name, 'main_name')

    except Exception as e:
        logger.error(f"An error occurred in main execution: {e}")
    finally:
        # Retrieve logs from the handler
        all_logs = csv_error_handler.get_all_logs()
        error_logs = csv_error_handler.get_error_logs()
        # Save all logs and error logs to Blob Storage
        if all_logs:
            all_logs_df = pd.DataFrame(all_logs)
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-enterprises-pe-a-record-associted-private-dns-zone', 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-enterprises-pe-a-record-associted-private-dns-zone', 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('azure-enterprises-pe-a-record-associted-private-dns-zone', 'azure-enterprises-pe-a-record-associted-private-dns-zone' +' Error Report', "excel", 'azure-enterprises-pe-a-record-associted-private-dns-zone', error_logs_df)


if __name__ == "__main__":
    main()
