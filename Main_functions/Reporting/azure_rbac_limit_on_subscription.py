import logging
import os
import sys
sys.path.append('.')
import pandas as pd
from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
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

 
# Define the RBAC limit and threshold
RBAC_LIMIT = 4000
THRESHOLD = 0.89 * RBAC_LIMIT
 
def process_subscription(subscription, credential):
    try:
        subscription_name = subscription.display_name
        print(subscription_name)
        subscription_id = subscription.subscription_id
        auth_client = AuthorizationManagementClient(credential, subscription_id)
        resource_client = ResourceManagementClient(credential, subscription_id)
        subscription_tags = resource_client.tags.get_at_scope(f"/subscriptions/{subscription_id}")
        sub_tags = subscription_tags.properties.tags
        
        # Fetch the role assignments count at subscription level
        role_assignments = list(auth_client.role_assignments.list_for_scope(f"/subscriptions/{subscription_id}"))
       
        count = 0
        for r in role_assignments:
            if 'Microsoft.Management' not in r.scope and r.scope !='/':
                count = count +1
        #print({subscription_name},{count})
               
        # Check if RBAC count exceeds the threshold
        if count > THRESHOLD:
            cst_time = datetime.utcnow() - timedelta(hours=6)
            cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')

            return {
                'SubscriptionName': str(subscription_name),
                'Subscription_ID': str(subscription_id),
                'RBAC_Count': str(count),
                'Sub_Tag': str(sub_tags) if sub_tags else "N/A",
                'Timestamp': str(cst_time_str)
            }
        else:
            return None
 
    except Exception as e:
       logger.error(f"An error occurred during subscription {subscription_name} processing: {e}")
    return None
 
def check_rbac_counts():
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
 
        rbac_reports = []
 
        with ThreadPoolExecutor() as executor:
            results = executor.map(lambda sub: process_subscription(sub, credential), subscriptions)
            for result in results:
                if result:
                    rbac_reports.append(result)
 
        df = pd.DataFrame(rbac_reports)
        table_name = 'azure_rbac_limit_on_subscription'
        columns = ['SubscriptionName','Subscription_ID', 'RBAC_Count', 'Sub_Tag', 'Timestamp']
        container_name = 'azure-rbac-limit-on-subscription'
        if rbac_reports:
            notifications_email.send_email(container_name, container_name +' Data Report', "excel", container_name, df)
            Azure_SQL_Convertion.SQL_function(df, table_name, columns)
            Azure_Blob_Convertion.Blob_function(df, container_name, 'main_name')
 
    except Exception as e:
        logger.error(e)
    finally:
        # Retrieve logs from the handler
        all_logs = csv_error_handler.get_all_logs()
        error_logs = csv_error_handler.get_error_logs()
        # Save all logs and error logs to Blob Storage
        if all_logs:
            all_logs_df = pd.DataFrame(all_logs)
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-rbac-limit-on-subscription', 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-rbac-limit-on-subscription', 'error_logs')
            logger.info(f"Error logs generated for CSV")
            notifications_email.send_email('azure-rbac-limit-on-subscription', 'azure-rbac-limit-on-subscription' +' Error Report', "excel", 'azure-rbac-limit-on-subscription', error_logs_df)

 
if __name__ == "__main__":
    check_rbac_counts()

