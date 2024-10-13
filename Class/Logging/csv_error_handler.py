import logging
from datetime import datetime

class CSVErrorHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.all_logs = []
        self.error_logs = []

    def emit(self, record):
        log_entry = self.format(record)
        if record.levelname == 'ERROR':
            self.error_logs.append({
                'Timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'Level': record.levelname,
                'Message': log_entry
            })
        else:
            self.all_logs.append({
                'Timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'Level': record.levelname,
                'Message': log_entry
            })

    def get_all_logs(self):
        return self.all_logs

    def get_error_logs(self):
        return self.error_logs
