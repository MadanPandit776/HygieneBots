import pyodbc
import os
import sys
import pandas as pd
import logging
sys.path.append('.')
from Class.Email import notifications_email
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from Class.Report_handler.config_param import Config

# Set up logging
logging.basicConfig(filename='app.log', filemode='a', format='%(asctime)s - %(levelname)s - %(message)s', level=logging.ERROR)

# Function to dynamically determine appropriate data type for SQL column based on data length
def determine_sql_data_type(max_length):
    if max_length <= 8000:
        return "NVARCHAR(MAX)"
    else:
        # If data length exceeds 8000, consider using TEXT or VARCHAR(MAX) data type
        return "TEXT"  # Or VARCHAR(MAX) depending on your requirements

def SQL_function(df, table_name, columns):
    conn = None
    try:
        credential = DefaultAzureCredential()
        keyvault_url = Config.keyvault_url
        secret_client = SecretClient(vault_url=keyvault_url, credential=credential)

        SqlServerAdminUserName = Config.SqlServerAdminUserName
        SqlServerName = Config.SqlServerName
        SqlServerAdminPassword = Config.SqlServerAdminPassword
        SqlServerdatabase = Config.SqlServerdatabase

        ServerAdmin = secret_client.get_secret(SqlServerAdminUserName)
        ServerName = secret_client.get_secret(SqlServerName)
        ServerPass = secret_client.get_secret(SqlServerAdminPassword)
        ServerDB = secret_client.get_secret(SqlServerdatabase)

        username = ServerAdmin.value
        server = ServerName.value
        password = ServerPass.value
        database = ServerDB.value
     
        
        # Establish connection
        #conn = pyodbc.connect(connection_string)
        
        driver = '{ODBC Driver 17 for SQL Server}'
        conn_str = f'DRIVER={driver};SERVER={server};PORT=1433;DATABASE={database};UID={username};PWD={password};Authentication=ActiveDirectoryPassword'
        conn = pyodbc.connect(conn_str)
        
        cursor = conn.cursor()

        # Create the table if it doesn't exist
        table_exists_query = f"SELECT 1 FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = '{table_name}'"
        cursor.execute(table_exists_query)
        table_exists = cursor.fetchone()
        if not table_exists:
            create_table_query = f'''
                CREATE TABLE {table_name} (
                    ID INT IDENTITY(1,1) PRIMARY KEY,
                    {', '.join([f"{col} NVARCHAR(MAX)" for col in columns])}
                )
            '''
            cursor.execute(create_table_query)
            conn.commit()

        # Get maximum lengths of data in DataFrame columns
        max_lengths = []
        for col in df.columns:
            try:
                max_len = max(map(len, df[col]))
            except Exception as len_error:
                print(f"Error calculating length for column '{col}': {len_error}")
                max_len = 0
            max_lengths.append(max_len)

        # Alter table to increase column lengths if necessary
        for column, max_length in zip(columns, max_lengths):
            try:
                # Determine appropriate SQL data type for the column
                sql_data_type = determine_sql_data_type(max_length)
                alter_column_query = f"ALTER TABLE {table_name} ALTER COLUMN {column} {sql_data_type}"
                cursor.execute(alter_column_query)
                conn.commit()
            except Exception as alter_error:
                print(f"Error altering column '{column}': {alter_error}")
                # Log the error
                logging.error(f"Error altering column '{column}': {alter_error}")
                # Handle the error as needed

        # Prepare data for bulk insert
        data_to_insert = [tuple(row) for row in df.values.tolist()]

        # Insert the data into the table
        insert_query = f"""
            INSERT INTO {table_name} ({', '.join(columns)})
            VALUES ({', '.join(['?' for _ in columns])})
        """
        cursor.executemany(insert_query, data_to_insert)
        conn.commit()

        print("Data inserted successfully.")
    except Exception as e:
        print("Error:", e)
        # Log the error
        logging.error(f"Error in SQL_function: {e}")
        # Optionally, you can also send an email notification
        notifications_email.send_email("SQL Connectivity Failed", f"Error : {e}", "Error")
        # notifiyemail.create_excel_and_send_email(None, "Exception", str(e), "test")
    finally:
        if conn:
            conn.close()

# Example usage:
# SQL_function(df, 'table_name', ['column1', 'column2', 'column3'])
