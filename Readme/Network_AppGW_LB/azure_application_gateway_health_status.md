# Azure Application Gateway Health Status Bot

## Overview
The Azure Application Gateway Health Status Bot is a Python script designed to fetch unhealthy backend pools in Azure Application Gateways across All Azure subscriptions. It utilizes Azure services such as Azure SQL and Azure Identity for authentication and data storage.

## Features

| Feature              | Details                                                 |
|----------------------|---------------------------------------------------------|
| **Naming convention**| azure_application_gateway_health_status                 |
| **Type**             | Scan-Report                                             |
| **Services**         | Security                                                |
| **Schedule run**     | Weekly                                                  |
| **Retention Period** | 1 year                                                  |
| **Primary Owner**    | Jaswinder Singh                                         |
| **Secondary Owner**  | Rajesh Nagapuri                                         |

- Fetches Azure Application Gateway Health Status.
- Utilizes Azure SQL for storing Azure Application Gateway Health Status details.
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
Follow these steps to set up the Azure Application Gateway Health Status Bot:

1. **Install Dependencies**: Ensure required Python packages are installed using pip:
   - `azure.identity`: [azure-identity](https://pypi.org/project/azure-identity)
   - `azure.mgmt.resource`: [azure-mgmt-resource](https://pypi.org/project/azure-mgmt-resource)
   - `azure.mgmt.network`: [azure-mgmt-network](https://pypi.org/project/azure-mgmt-network)
   
2. **Configure Azure Resources**:
   - **Azure Service Connection**: Set up in Azure DevOps.
   - **Azure SQL Database**: Create with necessary credentials.
   - **Azure Blob Storage**: Create an account and set retention policy to 7 days.
   
3. **Azure Pipeline Setup**: Use the provided YAML file (`azure-pipeline.yml`) for scheduled builds. Ensure correct configuration of `servicePrincipalId`, `servicePrincipalKey`, and `tenantId`.

## Bot Execution Steps
Follow these guidelines for using the Azure Application Gateway Health Status Bot:

1. **Install Required Plugins**: Install Python plugins like `azure.mgmt.network.NetworkManagementClient` to access Azure resources.

2. **Configure Subscription**: Modify the script to iterate through specified subscriptions.

3. **Execution**:
   - Azure Pipeline triggers the bot according to the defined schedule.
   - Azure Application Gateway Health Status details are stored in Azure SQL Database.
   - Data sheet, execution logs, and exceptions are stored in Azure Blob Storage.
   - Bot creates a new container in Azure Blob if it doesn't exist.

4. **Monitoring**:
   - Check Azure Pipeline logs for execution details.
   - Monitor Azure Blob Storage for logs and exceptions.
   - Review Azure SQL Database for Azure Application Gateway Health Status details.

   ## Email Notification (Regular/Failure)
The Azure Cross Origin Resource Sharing Bot includes email notification functionality to keep stakeholders informed about the execution status and any potential issues. Here's how it works:

- **Failure Notifications**: 
  - In case of any SQL or Blob connection issues during execution, or if data fails to import into the Azure SQL Database, the bot triggers a failure email notification. This notification alerts stakeholders about the encountered problem, allowing for timely investigation and resolution.

- **Report Email Notifications**: 
  - Additionally, the bot sends a detailed report via email after each execution, summarizing the Application Gateway Health Status fetched, any exceptions encountered, and the overall execution status. This report provides stakeholders with comprehensive insights into the bot's performance and any potential issues that need attention.

## Additional Documentation
For detailed instructions on configuring Azure Application Gateway Health Status, refer to the [Microsoft Azure documentation](https://learn.microsoft.com/en-us/azure/application-gateway/application-gateway-probe-overview).


