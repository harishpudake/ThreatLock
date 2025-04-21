
import psutil
import os
import time
from plyer import notification
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from Backend.desktop_alert import DesktopAlert



LOGS_DIR = r"C:\Windows\System32\winevt\Logs"

class LogFileDeletionHandler(FileSystemEventHandler):


    def generate_alert(self,):
        title = 'EDR: "LOGS FILES ARE BEING DELETED"'
        alert = DesktopAlert(title=title, msg=self.alert_msg, severity="Critical")
        alert.show_alert()


    def on_deleted(self, event):

        if event.is_directory:
            self.alert_msg = f'! Folder deleted = "{os.path.basename(event.src_path)}"' + '\n'
        else:
            self.alert_msg = f'! File deleted = "{os.path.basename(event.src_path)}"' + '\n'
        self.get_deleting_process()
        self.generate_alert()


    def get_deleting_process(self):
        try:
            # Iterate through all active processes
            for proc in psutil.process_iter(attrs=["pid", "name"]):
                try:
                    # Fetch the open files for the process
                    open_files = proc.open_files()
                    for f in open_files:
                        if LOGS_DIR in f.path:
                            self.alert_msg += f"! Process '{proc.info['name']}' (PID: {proc.info['pid']}) was interacting with the logs folder."
                            return
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue
            self.alert_msg += "! Could not identify the process responsible for deletion."
        except Exception as e:
            self.alert_msg += f"! Error identifying the deleting process: {e}"


def start_monitoring(path):
    if not os.path.exists(path):
        print(f"Error: The path {path} does not exist.")
        return
    
    event_handler = LogFileDeletionHandler()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    print(f"Monitoring started for deletions in: {path}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("Monitoring stopped.")
    observer.join()




# if __name__ == "__main__":
#     start_monitoring(LOGS_DIR)


