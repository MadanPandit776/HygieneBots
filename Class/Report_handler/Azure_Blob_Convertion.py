from azure.storage.blob import BlobServiceClient
from io import BytesIO
from datetime import datetime, timezone, timedelta
import pandas as pd
import sys
import os
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from openpyxl import Workbook

sys.path.append('.')
from Class.Email import notifications_email
from Class.Report_handler.config_param import Config

def create_container_if_not_exists(connection_string, container_name):
    try:
        blob_service_client = BlobServiceClient.from_connection_string(connection_string)
        container_client = blob_service_client.get_container_client(container_name)
        container_properties = container_client.get_container_properties()
        return container_client
    except Exception as e:
        print(f"Container '{container_name}' does not exist. Creating container...")
        container_client = blob_service_client.create_container(container_name)
        print(f"Container '{container_name}' created successfully.")
        return container_client

def Blob_function(df, name, status):
    try:
        # Define the connection string and container name
        credential = DefaultAzureCredential()

        keyvault_url = Config.keyvault_url
        secret_client = SecretClient(vault_url=keyvault_url, credential=credential)
        
        ReportingStorageAccountKey = Config.ReportingStorageAccountKey
        ReportingStorageName = Config.ReportingStorageName
        StrKey = secret_client.get_secret(ReportingStorageAccountKey)
        StrName = secret_client.get_secret(ReportingStorageName)
       
        account_key = StrKey.value
        account_name = StrName.value
        connection_string = f"DefaultEndpointsProtocol=https;AccountName={account_name};AccountKey={account_key};EndpointSuffix=core.windows.net"
        container_name = name

        # Create container if not exists
        container_client = create_container_if_not_exists(connection_string, container_name)
        cst_time = datetime.utcnow() - timedelta(hours=6)
        cst_time_str = cst_time.strftime('%Y-%m-%d %H-%M-%S CST-%H-%M')

        if status == "main_name":
            file = f'{name}_{cst_time_str}.xlsx'
        elif status == "all_logs":
            all_execution = "All_Execution_Logs"
            file = f'{all_execution}.xlsx'
        elif status == "error_logs":
            error_execution = "Error_Execution_Logs"
            file = f'{error_execution}.xlsx'

        # Check if the file exists in the blob storage
        blob_service_client = BlobServiceClient.from_connection_string(connection_string)
        blob_client = blob_service_client.get_blob_client(container_name, file)

        if blob_client.exists():
            # Download the existing file
            stream = blob_client.download_blob()
            byte_data = stream.readall()
            # Wrap the byte data in a BytesIO object
            bytes_io = BytesIO(byte_data)
            existing_df = pd.read_excel(bytes_io, engine='openpyxl')
            bytes_io.close()  # Explicitly close the BytesIO object

            # Append the new data to the existing DataFrame
            combined_df = pd.concat([existing_df, df], ignore_index=True)

            # Write the combined DataFrame to an Excel file
            output = BytesIO()
            with pd.ExcelWriter(output, engine='openpyxl') as writer:
                combined_df.to_excel(writer, index=False)
            output.seek(0)
            blob_client.upload_blob(output.getvalue(), overwrite=True)
            output.close()  # Explicitly close the BytesIO object
        else:
            # Create a new Excel file and upload the DataFrame
            output = BytesIO()
            with pd.ExcelWriter(output, engine='openpyxl') as writer:
                df.to_excel(writer, index=False)
            output.seek(0)
            blob_client.upload_blob(output.getvalue())
            output.close()  # Explicitly close the BytesIO object

        print(f"Upload successful! File name: {file}")

    except Exception as e:
        print(f"An error occurred: {e}")
        notifications_email.send_email("Blob Connectivity Issue", f"Error : {e}", "Error")
