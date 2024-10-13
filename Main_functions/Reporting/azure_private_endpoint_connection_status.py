import logging
import pandas as pd
import sys
import requests
import os
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.privatedns import PrivateDnsManagementClient
from azure.keyvault.secrets import SecretClient
sys.path.append('.')
from concurrent.futures import ThreadPoolExecutor
from Class.Report_handler.config_param import Config
from Class.Report_handler import Azure_SQL_Convertion
from Class.Report_handler import Azure_Blob_Convertion
from Class.Logging.csv_error_handler import CSVErrorHandler
from Class.Email import notifications_email

# Create lists to store logs
all_logs = []
error_logs = []

csv_error_handler = CSVErrorHandler()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(csv_error_handler)

# Azure authentication and client initialization
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


def get_dns_record_sets(subscription_id, resource_group_name, zone_name, token):
    try:
        url = f'https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.Network/privateDnsZones/{zone_name}/recordSets?api-version=2020-06-01'
        print(url)
        headers = {
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json'
        }
        response = requests.get(url, headers=headers)
        
        # Log status code and response content for debugging
        print(f"Status Code: {response.status_code}")
        print(f"Response Content: {response.content}")
        
        response.raise_for_status()
        record_sets = response.json()
        print(record_sets)
        ip_addresses = []
        for record_set in record_sets.get('value', []):
            fqdn = record_set.get('properties', {}).get('fqdn')
            # Check for 'aRecords' instead of 'ipAddresses'
            a_records = record_set.get('properties', {}).get('aRecords', [])
            for record in a_records:
                ip_addresses.append({'ipAddress': record.get('ipv4Address')})
                #ip_addresses.append({'fqdn': fqdn, 'ipAddress': record.get('ipv4Address')})
        return ip_addresses
    except requests.exceptions.HTTPError as http_err:
        logging.error(f"HTTP error occurred: {http_err}")
    except Exception as e:
        logging.error(f"Failed to get DNS record sets: {e}")
    return []

def resolve_spn_name(sub_id, rg_name, private_endpoint_name):

    try:
        dns_zone_ids = []
        token_url = f"https://login.microsoftonline.com/{ValueTenant}/oauth2/token"
        #token_url = "https://login.microsoftonline.com/{ValueTenant}/oauth2/token"
        
        # Define the parameters for the POST request
        params = {
            'grant_type': 'client_credentials',
            'client_id': ValueCLientID,
            'client_secret': VAlueClientSecret,
            'resource': 'https://management.azure.com'
        }

        # Make the POST request
        response = requests.post(token_url, data=params)
        response.raise_for_status()  # Raise an exception for 4xx/5xx status codes

        # Extract access token
        token = response.json()['access_token']

        # Construct the private DNS zone API URL
        
        private_dns_zone = f'https://management.azure.com/subscriptions/{sub_id}/resourcegroups/{rg_name}/providers/microsoft.network/privateendpoints/{private_endpoint_name}/privateDnsZoneGroups?api-version=2021-05-01'

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

        return dns_zone_ids,token

    except Exception as e:
        logging.error(f"Failed to resolve SPN name: {e}")
        return None

def process_subscription(subscription):
    try:
        subscription_id = subscription.subscription_id
        subscription_name = subscription.display_name

        # Initialize clients
        resource_client = ResourceManagementClient(credentials, subscription_id)
        network_client = NetworkManagementClient(credentials, subscription_id)
        dns_client = PrivateDnsManagementClient(credentials, subscription_id)

        # Fetch private DNS zones
        private_dns_zones = dns_client.private_zones.list()
        dns_zone_names = [zone.name for zone in private_dns_zones]

        results = []

        # Retrieve resource groups
        resource_groups = resource_client.resource_groups.list()

        for resource_group in resource_groups:
            resource_group_name = resource_group.name

            # Retrieve private endpoints in the resource group
            private_endpoints = network_client.private_endpoints.list(resource_group_name)

            for private_endpoint in private_endpoints:
                cst_time = datetime.utcnow() - timedelta(hours=6)
                cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
                private_endpoint_name = private_endpoint.name
                private_link_connection_state = private_endpoint.private_link_service_connections[0].private_link_service_connection_state.status if private_endpoint.private_link_service_connections else "Unknown"
                #private_ip_address = private_endpoint.ip_configurations[0].private_ip_address if private_endpoint.ip_configurations else "No IP Configurations"
                dns_zone_details, token = resolve_spn_name(subscription_id, resource_group_name, private_endpoint.name)
                private_ip_address = None
                for nic in private_endpoint.network_interfaces:
                        network_interface = network_client.network_interfaces.get(resource_group_name, nic.id.split('/')[-1])
                        if network_interface.ip_configurations:
                            private_ip_address = network_interface.ip_configurations[0].private_ip_address
                            break
               

                # ip_addresses = []
                # for zone_id in dns_zone_details or []:
                #     zone_name = zone_id.split('/')[-1]
                #     zonerg = zone_id.split('/')[4]
                #     ip_addresses += get_dns_record_sets(subscription_id, zonerg, zone_name, token)


                # Extract DNS zone details
                dns_zone_name = None
                dns_zone_sub_value = None
                dns_zone_rg = None
                for zonedetail in dns_zone_details or []:
                    dns_zone_name = zonedetail.split('/')[-1]
                    dns_zone_sub_value = subscription_client.subscriptions.get(zonedetail.split('/')[2]).display_name
                    dns_zone_rg = zonedetail.split('/')[4]

                # Retrieve private link details
                private_link_connection = private_endpoint.private_link_service_connections[0]
                private_link_resource_type = private_link_connection.private_link_service_id.split("/")[6]

                # Collect results
                results.append({
                    "SubscriptionName": str(subscription_name),
                    "Subscription": str(subscription_id),
                    "ResourceGroup": str(resource_group_name),
                    "ConnectionState": str(private_link_connection_state),
                    "PrivateEndpointName": str(private_endpoint_name),
                    "PrivateDNSZone": str(dns_zone_name),
                    "PrivateDNSZone_Sub": str(dns_zone_sub_value),
                    "PrivateDNSZone_RG": str(dns_zone_rg),
                    "Resource Type": str(private_link_resource_type),
                    "Resource Name": str(private_link_connection.private_link_service_id.split('/')[-1]),
                    "VNET": str(private_endpoint.subnet.id.split('/')[-3]),
                    "Subnet": str(private_endpoint.subnet.id.split('/')[-1]),
                    "IP": str(private_ip_address),
                    "Tag": str(private_endpoint.tags),
                    "Timestamp": str(cst_time_str)
                })
                logging.info(f"process private endpoint {private_endpoint_name}")


        return results

    except Exception as e:
        logging.error(f"Failed to process subscription {subscription.display_name}: {e}")
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
                    logging.error(f"Error processing subscription: {e}")

        # Convert results to DataFrame
        df = pd.DataFrame(all_results)
        table_name = 'azure_private_endpoint_connection_status'
        container_name = 'azure-private-endpoint-connection-status'
        
        columns = ['SubscriptionName', 'Subscription', 'ResourceGroup', 'ConnectionState', 'PrivateEndpointName', 'PrivateDNSZone','PrivateDNSZone_Sub', 'PrivateDNSZone_RG','Resource_Type', 'Resource_Name', 'VNET', 'Subnet', 'IP', 'Tag','Timestamp']
        if all_results:
            Azure_SQL_Convertion.SQL_function(df, table_name, columns)
            Azure_Blob_Convertion.Blob_function(df, container_name, 'main_name')
            notifications_email.send_email(container_name, container_name + ' Data Report', "excel", container_name, df)

    except Exception as e:
        logging.error(f"An error occurred in main execution: {e}")
    finally:
        # Retrieve logs from the handler
        all_logs = csv_error_handler.get_all_logs()
        error_logs = csv_error_handler.get_error_logs()
        # Save all logs and error logs to Blob Storage
        if all_logs:
            all_logs_df = pd.DataFrame(all_logs)
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-private-endpoint-connection-status', 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-private-endpoint-connection-status', 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('Exception log file generated', 'azure-private-endpoint-connection-status' +' Exception Report', "excel", 'azure-private-endpoint-connection-status', error_logs_df)


if __name__ == "__main__":
    main()
