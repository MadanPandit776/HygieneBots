# Azure Firewall Allowed Public IP In Storage Account, key Vault, Event Hubs & SQL database

## Overview
The Azure storage, key Vault, Event Hubs & SQL database firewall provides access control for the public endpoint of storage, key Vault, Event Hubs & SQL database. It can also be use to block all access through the public endpoint when you're using private endpoints.The firewall configuration also enables trusted Azure platform services to access the storage account,key Vault, Event Hubs & SQL database.The Python script designed to fetch the Azure Firewall IP Rules for various Azure resources such as Storage Accounts, Key Vaults, and Event Hubs & SQL database across all Azure subscriptions.

## Features

| Feature              | Details                                                      |
|----------------------|------------------------------------------------------------- |
| **Naming convention**| azure_firewall_allowed_public_ip_in_storage_keyvault_eventhub|
| **Type**             | Scan-Report                                                  |
| **Services**         | Security                                                     |
| **Schedule run**     | Weekly                                                       |
| **Retention Period** | 1 year                                                       |
| **Primary Owner**    | Jaswinder Singh                                              |
| **Secondary Owner**  | Rajesh Nagapuri                                              |

- Fetches Azure Firewall Allowed Public IP In Storage Account, key Vault, Event Hubs & SQL database.
- Utilizes Azure SQL for Azure Firewall Allowed Public IP In Storage Account, key Vault, Event Hubs & SQL database details.
- Stores data sheet, execution logs, and exceptions in Azure Blob with a 7-day retention period.
- Automated execution via Azure Pipeline.
- Supports authentication via Azure Service Connection.

## Prerequisites
Before starting, ensure you have the following prerequisites:

- Python 3.x installed.
- Azure subscription(s) with appropriate permissions.
- Azure SQL Database.
- Azure Blob Storage.
- Azure Service Connection in Azure DevOps.
- Azure Pipeline configured for scheduled builds.

## Setup
Follow these steps to set up the Azure Firewall Allowed Public IP In Storage Account, key Vault, Event Hubs & SQL database Bot:

1. **Install Dependencies**: Ensure required Python packages are installed using pip:
   - `azure.identity`: [azure-identity](https://pypi.org/project/azure-identity)
   - `azure.mgmt.resource`: [azure-mgmt-resource](https://pypi.org/project/azure-mgmt-resource)
   - `azure.mgmt.storage`: [azure-mgmt-storage](https://pypi.org/project/azure-mgmt-storage)
   - `azure.mgmt.keyvault`: [azure-mgmt-keyvault](https://pypi.org/project/azure-mgmt-keyvault)
   - `azure.mgmt.eventhub`: [azure-mgmt-storage](https://pypi.org/project/azure-mgmt-eventhub)
   
2. **Configure Azure Resources**:
   - **Azure Service Connection**: Set up in Azure DevOps.
   - **Azure SQL Database**: Create with necessary credentials.
   - **Azure Blob Storage**: Create an account and set retention policy to 7 days.
   
3. **Azure Pipeline Setup**: Use the provided YAML file (`azure-pipeline.yml`) for scheduled builds. Ensure correct configuration of `servicePrincipalId`, `servicePrincipalKey`, and `tenantId`.

## Bot Execution Steps
Follow these guidelines for using the Azure Firewall Allowed Public IP In Storage Account, key Vault, Event Hubs & SQL database Bot:

1. **Install Required Plugins**: Install Python plugins like `azure.mgmt.storage.StorageManagementClient`, `azure.mgmt.keyvault.KeyVaultManagementClient`, `azure.mgmt.eventhub.EventHubManagementClient` to access Azure resources.

2. **Configure Subscription**: Modify the script to iterate through specified subscriptions.

3. **Execution**:
   - Azure Pipeline triggers the bot according to the defined schedule.
   - Details on Firewall Allowed Public IPs are stored in Azure SQL Database.
   - Data sheet, execution logs, and exceptions are stored in Azure Blob Storage.
   - Bot creates a new container in Azure Blob if it doesn't exist.

4. **Monitoring**:
   - Check Azure Pipeline logs for execution details.
   - Monitor Azure Blob Storage for logs and exceptions.
   - Review Azure SQL Database for Firewall Allowed Public IP details.

   ## Email Notification (Regular/Failure)
The Azure Cross Origin Resource Sharing Bot includes email notification functionality to keep stakeholders informed about the execution status and any potential issues. Here's how it works:

- **Failure Notifications**: 
  - In case of any SQL or Blob connection issues during execution, or if data fails to import into the Azure SQL Database, the bot triggers a failure email notification. This notification alerts stakeholders about the encountered problem, allowing for timely investigation and resolution.

- **Report Email Notifications**: 
  - Additionally, the bot sends a detailed report via email after each execution, summarizing the Firewall Allowed Public IP fetched, any exceptions encountered, and the overall execution status. This report provides stakeholders with comprehensive insights into the bot's performance and any potential issues that need attention.

## Additional Documentation
For detailed instructions on configuring Firewall Allowed Public IP In Storage Account, key Vault, Event Hubs & SQL database, refer to the [Microsoft Azure documentation](https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security?tabs=azure-portal)(https://learn.microsoft.com/en-us/azure/key-vault/general/network-security)(https://learn.microsoft.com/en-us/azure/event-hubs/event-hubs-ip-filtering).


