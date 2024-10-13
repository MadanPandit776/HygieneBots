from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import SubscriptionClient
import sys

credential = DefaultAzureCredential()
subscription_client = SubscriptionClient(credential)

def check_valid_subscription_names(subscription_names):
    valid_subscriptions = []
    invalid_subscriptions = []

    all_subscriptions = list(subscription_client.subscriptions.list())
    all_subscription_names = [s.display_name for s in all_subscriptions]

    print("All Subscription Names from Azure:")
    #print(all_subscription_names)  # Print all subscription names fetched from Azure

    for name in subscription_names:
        if name in all_subscription_names:
            valid_subscriptions.append(name)
        else:
            invalid_subscriptions.append(name)

    return valid_subscriptions, invalid_subscriptions



