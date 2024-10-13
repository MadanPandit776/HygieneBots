# Azure Cross Origin Resource Sharing Bot

## Overview
The Azure Cross Origin Resource Sharing (CORS) Bot is a Python script designed to manage and monitor Cross-Origin Resource Sharing settings for Azure Web Apps, Function Apps, and API Apps. CORS is a crucial aspect of web security, allowing web applications to make requests to another domain. This bot ensures that CORS settings are configured with allowed origins specified, enhancing the security and functionality of Azure applications across all subscriptions.

## Features

| Feature              | Details                                                 |
|----------------------|---------------------------------------------------------|
| **Naming convention**| azure_cross_origin_resource_sharing                     |
| **Type**             | Scan-Report                                             |
| **Services**         | Security                                                |
| **Schedule run**     | Weekly                                                  |
| **Retention Period** | 1 year                                                  |
| **Primary Owner**    | Jaswinder Singh                                         |
| **Secondary Owner**  | Rajesh Nagapuri                                         |

- Fetches CORS settings only if allowed origins are configured.
- Utilizes Azure SQL for storing CORS details.
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
Follow these steps to set up the Azure Cross Origin Resource Sharing Bot:

1. **Install Dependencies**: Ensure required Python packages are installed using pip:
   - `azure.identity`: [azure-identity](https://pypi.org/project/azure-identity)
   - `azure.mgmt.resource`: [azure-mgmt-resource](https://pypi.org/project/azure-mgmt-resource)
   - `azure.mgmt.web`: [azure-mgmt-web](https://pypi.org/project/azure-mgmt-web)
   
2. **Configure Azure Resources**:
   - **Azure Service Connection**: Set up in Azure DevOps.
   - **Azure SQL Database**: Create with necessary credentials.
   - **Azure Blob Storage**: Create an account and set retention policy to 7 days.
   
3. **Azure Pipeline Setup**: Use the provided YAML file (`azure-pipeline.yml`) for scheduled builds. Ensure correct configuration of `servicePrincipalId`, `servicePrincipalKey`, and `tenantId`.

## Bot Execution Steps
Follow these guidelines for using the Azure Cross Origin Resource Sharing Bot:

1. **Install Required Plugins**: Install Python plugins like `azure.mgmt.web.WebSiteManagementClient` to access Azure resources.

2. **Configure Subscription**: Modify the script to iterate through specified subscriptions.

3. **Execution**:
   - Azure Pipeline triggers the bot according to the defined schedule.
   - Details on CORS settings with allowed origins are stored in Azure SQL Database.
   - Data sheet, execution logs, and exceptions are stored in Azure Blob Storage.
   - Bot creates a new container in Azure Blob if it doesn't exist.

4. **Monitoring**:
   - Check Azure Pipeline logs for execution details.
   - Monitor Azure Blob Storage for logs and exceptions.
   - Review Azure SQL Database for CORS settings details.

## Additional Documentation
For detailed instructions on configuring CORS settings for Azure Web Apps, Function Apps, and API Apps, refer to the [Microsoft Azure documentation](https://learn.microsoft.com/en-us/cli/azure/webapp/cors?view=azure-cli-latest).

