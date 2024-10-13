# Azure VM Configured With ASR Bot

## Overview
The Azure VM Configured With ASR Bot is a Python script designed to fetch details about Virtual Machines (VMs) that are configured with Azure Site Recovery across All Azure subscriptions. It utilizes Azure services such as Azure SQL and Azure Identity for authentication and data storage.

## Features

| Feature              | Details                                                 |
|----------------------|---------------------------------------------------------|
| **Naming convention**| azure_vm_with_asr                                       |
| **Type**             | Scan-Report                                             |
| **Services**         | Security                                                        |
| **Schedule run**     | Daily                                                        |
| **Retention Period** | 1 year                                                  |
| **Primary Owner**    | Jaswinder Singh                                         |
| **Secondary Owner**  | Rajesh Nagapuri                                         |

- Fetches Azure VMs configured with Azure Site Recovery (ASR) across all Azure subscriptions.
- Utilizes Azure SQL for storing VM Configured With ASR details.
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
Follow these steps to set up the Azure VM Configured With ASR Bot:

1. **Install Dependencies**: Ensure required Python packages are installed using pip:
   - `azure.identity`: [azure-identity](https://pypi.org/project/azure-identity)
   - `azure.mgmt.recoveryservices`: [azure-mgmt-recoveryservices](https://pypi.org/project/azure-mgmt-recoveryservices)
   - `azure.mgmt.recoveryservicessiterecovery`: [azure-mgmt-recoveryservicessiterecovery](https://pypi.org/project/azure-mgmt-recoveryservicessiterecovery)
   - `azure.mgmt.compute`: [azure-mgmt-compute](https://pypi.org/project/azure-mgmt-compute)
   
2. **Configure Azure Resources**:
   - **Azure Service Connection**: Set up in Azure DevOps.
   - **Azure SQL Database**: Create with necessary credentials.
   - **Azure Blob Storage**: Create an account and set retention policy to 7 days.
   
3. **Azure Pipeline Setup**: Use the provided YAML file (`azure-pipeline.yml`) for scheduled builds. Ensure correct configuration of `servicePrincipalId`, `servicePrincipalKey`, and `tenantId`.

## Bot Execution Steps
Follow these guidelines for using the Azure VM Configured With ASR Bot:

1. **Install Required Plugins**: Install Python plugins like `azure.mgmt.compute.ComputeManagementClient` to access Azure resources.

2. **Configure Subscription**: Modify the script to iterate through specified subscriptions.

3. **Execution**:
   - Azure Pipeline triggers the bot according to the defined schedule.
   - Details on VM Configured With ASR are stored in Azure SQL Database.
   - Data sheet, execution logs, and exceptions are stored in Azure Blob Storage.
   - Bot creates a new container in Azure Blob if it doesn't exist.

4. **Monitoring**:
   - Check Azure Pipeline logs for execution details.
   - Monitor Azure Blob Storage for logs and exceptions.
   - Review Azure SQL Database for VM Configured With ASR details.

   ## Email Notification (Regular/Failure)
The Azure VM Configured With ASR Bot includes email notification functionality to keep stakeholders informed about the execution status and any potential issues. Here's how it works:

- **Failure Notifications**: 
  - In case of any SQL or Blob connection issues during execution, or if data fails to import into the Azure SQL Database, the bot triggers a failure email notification. This notification alerts stakeholders about the encountered problem, allowing for timely investigation and resolution.

- **Report Email Notifications**: 
  - Additionally, the bot sends a detailed report via email after each execution, summarizing theVM Configured With ASR fetched, any exceptions encountered, and the overall execution status. This report provides stakeholders with comprehensive insights into the bot's performance and any potential issues that need attention.

## Additional Documentation
For detailed instructions on configuring VM Configured With ASR, refer to the [Microsoft Azure documentation](https://learn.microsoft.com/en-us/azure/site-recovery/azure-to-azure-tutorial-enable-replication).


