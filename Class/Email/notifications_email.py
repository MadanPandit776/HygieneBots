import os
import pandas as pd
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import sys
sys.path.append('.')
from Class.Report_handler.config_param import Config


def send_email(subject, email_body, email_type, excel_file_name=None, dataframe=None):
    try:
        sender_email = Config.sender_email
        receiver_email = Config.receiver_email
        smtp_server = Config.smtp_server
        
        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = receiver_email
        message["Subject"] = subject

        email_content = f"""
        <html>
          <head>
            <style>
              /* Define your CSS styles here */
              body {{
                font-family: Arial, sans-serif;
                line-height: 1.6;
                margin: 20px;
              }}
              .header {{
                background-color: #007bff;
                color: white;
                padding: 10px;
                text-align: center;
              }}
              .content {{
                padding: 20px;
                background-color: #f0f0f0;
                border-radius: 5px;
              }}
              .footer {{
                text-align: center;
                margin-top: 20px;
                color: #888888;
              }}
            </style>
          </head>
          <body>
            <div class="header">
              <h2>{subject}</h2>
            </div>
            <div class="content">
              <p>{email_body}</p>
              <p>Regards,<br>CloudBot</p>
            </div>
            <div class="footer">
              <p>Sent via CloudBot at PepsiCo</p>
            </div>
          </body>
        </html>
        """

        if email_type == 'excel':
            if dataframe is None:
                raise ValueError("DataFrame cannot be None when email_type is 'excel'")
            
            # Convert DataFrame to Excel
            excel_file_path = excel_file_name + '.xlsx'
            dataframe.to_excel(excel_file_path, index=False)

            with open(excel_file_path, "rb") as attachment:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(attachment.read())

            encoders.encode_base64(part)
            part.add_header(
                "Content-Disposition",
                f"attachment; filename= {excel_file_path}",
            )
            message.attach(MIMEText(email_content, "html"))
            message.attach(part)
        elif email_type == "Error":
            # Add body to email if not 'excel' type
            message.attach(MIMEText(email_content, "html"))

        # Convert message to string
        text = message.as_string()

        # Connect to SMTP server and send email
        with smtplib.SMTP(smtp_server, 25) as server:
            server.sendmail(sender_email, receiver_email, text)
        
        print("Email sent successfully")

    except Exception as e:
        print(f"Failed to send email: {e}")
    finally:
        # Remove temporary Excel file if it was created
        if email_type == 'excel' and os.path.exists(excel_file_path):
            os.remove(excel_file_path)

