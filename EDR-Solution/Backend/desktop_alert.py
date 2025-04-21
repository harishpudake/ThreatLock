import csv 
import os 
from datetime import datetime
from plyer import notification


class DesktopAlert():
    def __init__(self, title, msg, severity = "Medium"):
        self.title =  title
        self.msg = msg
        self.severity = severity

    def show_alert(self):
        notification.notify(
            title=self.title,
            message=self.msg,
        )
        self.log_alert()

    def log_alert(self):
        """Logs the alert into a CSV file with UTF-8 encoding."""
        file_path = "alert_history.csv"
        file_exists = os.path.exists(file_path)

        with open(file_path, mode="a", newline="", encoding="utf-8") as file:  # Ensuring UTF-8 encoding
            writer = csv.writer(file)

            # Write header only if the file is newly created
            if not file_exists:
                writer.writerow(["Timestamp", "Title", "Severity", "Description"])

            writer.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), self.title, self.severity, self.msg])