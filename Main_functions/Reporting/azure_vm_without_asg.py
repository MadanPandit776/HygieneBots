import logging
import os
import sys
sys.path.append('.')
from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import SubscriptionClient
from datetime import datetime, timedelta
import pandas as pd
from concurrent.futures import ThreadPoolExecutor
from Class.Report_handler import Azure_SQL_Convertion
from Class.Report_handler import Azure_Blob_Convertion
from Class.Logging.csv_error_handler import CSVErrorHandler
from Class.Email import notifications_email
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
    try:
        subscription_name = subscription.display_name
        subscription_id = subscription.subscription_id
        compute_client = ComputeManagementClient(credential, subscription_id)
        network_client = NetworkManagementClient(credential, subscription_id)

        vms_not_in_asg = []

        vms = compute_client.virtual_machines.list_all()

        for vm in vms:
            try:
                vm_name = vm.name
                vm_resource_group = vm.id.split('/')[4]
                location = vm.location
                network_interfaces = vm.network_profile.network_interfaces

                for nic in network_interfaces:
                    nic_id = nic.id
                    nic_resource_group = nic_id.split('/')[4]
                    nic_name = nic_id.split('/')[-1]

                    network_interface = network_client.network_interfaces.get(nic_resource_group, nic_name)
                    asgs = network_interface.ip_configurations[0].application_security_groups

                    asg_status = "Not Member"
                    if asgs:
                        asg_status = "Member"
                        break
                
                if asg_status == "Not Member":
                    cst_time = datetime.utcnow() - timedelta(hours=6)
                    cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
                    vms_not_in_asg.append({
                        'SubscriptionName': subscription_name,
                        'Subscription': subscription_id,
                        'ResourceGroup': vm_resource_group,
                        'VMName': vm_name,
                        "Location": location,
                        "asg_status":  asg_status,
                        'Timestamp': cst_time_str
                    })
                    logger.info(f"processing VM {vm.name}")
            except Exception as vm_error:
                logger.error(f"An error occurred while processing VM {vm.name}: {vm_error}")

        return vms_not_in_asg

    except Exception as e:
        logger.error(f"An error occurred during subscription {subscription.display_name} processing: {e}")
        return []

def list_vms_not_in_asg():
    try:
        # Initialize Azure credentials
        credential = DefaultAzureCredential()
        #credential = DefaultAzureCredential(exclude_managed_identity_credential=True)
        subscription_client = SubscriptionClient(credential)

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

        vms_not_in_asg = []

        with ThreadPoolExecutor() as executor:
            results = executor.map(lambda sub: process_subscription(sub, credential), subscriptions)
            for result in results:
                vms_not_in_asg.extend(result)

        # Create a DataFrame from the list of VMs not in ASGs
        df = pd.DataFrame(vms_not_in_asg)
        # Save results to Azure SQL and Blob Storage
        table_name = 'azure_vm_without_asg'
        container_name = 'azure-vm-without-asg'
        columns = ['SubscriptionName','Subscription', 'ResourceGroup', 'VMName', 'Location', 'asg_status', 'Timestamp']
        if vms_not_in_asg: 
         Azure_SQL_Convertion.SQL_function(df, table_name, columns)
         Azure_Blob_Convertion.Blob_function(df, container_name, 'main_name')
         notifications_email.send_email(container_name, container_name +' Data Report', "excel", container_name, df)

    except Exception as e:
        logger.error(f"Error occurred: {e}")
    finally:
        # Retrieve logs from the handler
        all_logs = csv_error_handler.get_all_logs()
        error_logs = csv_error_handler.get_error_logs()
        # Save all logs and error logs to Blob Storage
        if all_logs:
            all_logs_df = pd.DataFrame(all_logs)
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-vm-without-asg', 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-vm-without-asg', 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('Exception log file generated', 'azure-vm-without-asg' +' Exception Report', "excel", 'azure-vm-without-asg', error_logs_df)

if __name__ == "__main__":
    list_vms_not_in_asg()
