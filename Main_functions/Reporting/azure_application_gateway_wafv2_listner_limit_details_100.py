import logging
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import SubscriptionClient
import pandas as pd
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
sys.path.append('.')
from Class.Report_handler import Azure_SQL_Convertion
from Class.Report_handler import Azure_Blob_Convertion
from Class.Logging.csv_error_handler import CSVErrorHandler
from Class.Email import notifications_email
from Class.Logging import subscriptions_validations

# Create lists to store logs
all_logs = []
error_logs = []
waf_limit_details = []
# Instantiate the handler
csv_error_handler = CSVErrorHandler()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(csv_error_handler)

def check_appgw_listener_waf_v2_limit():
    try:
        # Initialize Azure credentials
        credential = DefaultAzureCredential()
        subscription_client = SubscriptionClient(credential)
       
        waf_limit_details = []
        # Get user input for choice of subscriptions
        user_input = sys.argv[1] if len(sys.argv) > 1 else "all"
        # Get subscriptions based on user input
        if user_input.lower() == "all":
            subscriptions = subscription_client.subscriptions.list()
        else:
            # Get the subscriptions that match the user input
            subscription_names = [s.strip() for s in user_input.split(",")]
            subscriptions = subscription_client.subscriptions.list()
            subscriptions = [s for s in subscriptions if s.display_name in subscription_names]
            valid_subs, invalid_subs = subscriptions_validations.check_valid_subscription_names(subscription_names)
            if invalid_subs:
              logger.error(f"invalid input subscriptions {invalid_subs}")
        def process_appgw(subscription):
            try:
                subscription_name = subscription.display_name
                logger.info(f"Processing subscription {subscription_name}")
                subscription_id = subscription.subscription_id
                network_client = NetworkManagementClient(credential, subscription_id)
                # Get all application gateways in the subscription
                app_gateways = network_client.application_gateways.list_all()
                results = []
                for appgw in app_gateways:
                    appgw_name = appgw.name
                    appgw_rg = appgw.id.split('/')[4]
                    appgw_location = appgw.location
                    sku_name = appgw.sku.name
                    listener_count = sum(1 for listener in appgw.http_listeners if listener.protocol == 'Https')
                    cst_time = datetime.utcnow() - timedelta(hours=6)
                    cst_time_str = cst_time.strftime('%Y-%m-%d %H:%M:%S CST-%H-%M')
                   
                    # Check WAF V2 configuration
                    if appgw.web_application_firewall_configuration:
                        waf_config = appgw.web_application_firewall_configuration
                        if waf_config.rule_set_version is not None:
                            rule_set_version = float(waf_config.rule_set_version)
                            rule_type = appgw.web_application_firewall_configuration.rule_set_type
                            if float(rule_set_version) > 3.1:
                                waf_limit = 100
                                results.append({
                                    'SubscriptionName': str(subscription.display_name),
                                    'Subscription': str(subscription.subscription_id),
                                    'ResourceGroup': str(appgw_rg),
                                    'AppGW_Name': str(appgw_name),
                                    'AppGW_Location': str(appgw_location),
                                    'SKU_Name': str(sku_name),
                                    'Rule_Set_Type': str(rule_type),
                                    'Rule_Set_Version': str(rule_set_version),
                                    'Listener_Count': str(listener_count),
                                    'WAF_Limit': str(waf_limit),
                                    'Timestamp': str(cst_time_str)                                })
                                
                return results
            except Exception as e:
                logger.error(f"An error occurred in subscription {subscription.display_name}: {e}")
                return []

        # Execute in parallel using ThreadPoolExecutor
        with ThreadPoolExecutor() as executor:
            future_to_subscription = {executor.submit(process_appgw, sub): sub for sub in subscriptions}
            for future in as_completed(future_to_subscription):
                try:
                    result = future.result()
                    if result:
                        waf_limit_details.extend(result)
                except Exception as e:
                    logger.error(f"An error occurred {e}")

        # Create a DataFrame from the list of WAF limit details
        df = pd.DataFrame(waf_limit_details)
        table_name = 'azure_application_gateway_wafv2_listner_limit_100_details'
        container_name = 'azure-application-gateway-wafv2-listner-limit-100-details'
        columns = ['SubscriptionName', 'Subscription', 'ResourceGroup', 'AppGW_Name', 'AppGW_Location', 'SKU_Name', 'Rule_Set_Type', 'Rule_Set_Version', 'Listener_Count', 'WAF_Limit', 'Timestamp']
        
        if waf_limit_details: 
            Azure_SQL_Convertion.SQL_function(df, table_name, columns)
            Azure_Blob_Convertion.Blob_function(df, container_name, 'main_name')
            notifications_email.send_email(container_name, container_name +' Data Report', "excel", container_name, df)
    except Exception as e:
        print(f"Error occurred: {e}")
        logger.error(f"An error occurred {e}")
   
    finally:
        all_logs = csv_error_handler.get_all_logs()
        error_logs = csv_error_handler.get_error_logs()
        
        if all_logs:
            all_logs_df = pd.DataFrame(all_logs)
            Azure_Blob_Convertion.Blob_function(all_logs_df, 'azure-application-gateway-wafv2-listner-limit-100-details', 'all_logs')
            logger.info(f"All logs generated for CSV")

        if error_logs:
            error_logs_df = pd.DataFrame(error_logs)
            Azure_Blob_Convertion.Blob_function(error_logs_df, 'azure-application-gateway-wafv2-listner-limit-100-details', 'error_logs')
            notifications_email.send_email('Exception log file generated', 'azure-application-gateway-wafv2-listner-limit-100-details' +' Exception Report', "excel", 'azure-application-gateway-wafv2-listner-limit-100-details', error_logs_df)
            logger.info(f"Error logs generated for CSV")

# Call the function to check Application Gateways with WAF V2 limit
check_appgw_listener_waf_v2_limit()
