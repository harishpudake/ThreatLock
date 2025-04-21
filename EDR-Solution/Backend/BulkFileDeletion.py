import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from Backend.desktop_alert import DesktopAlert



class FileDeletionHandler(FileSystemEventHandler):
    def __init__(self, excluded_paths):
        self.deleted_files = {}
        self.deletion_threshold = 10
        self.excluded_paths = excluded_paths

    def on_deleted(self, event):
        if not event.is_directory:
            base_directory = os.path.dirname(event.src_path)

            # Skip excluded directories
            if any(base_directory.startswith(excluded) for excluded in self.excluded_paths):
                return

            # Initialize the deleted files list for the directory if not already present
            if base_directory not in self.deleted_files:
                self.deleted_files[base_directory] = []

            # Add the deleted file to the directory-specific list
            self.deleted_files[base_directory].append(event.src_path)

            # Check if the threshold is reached for this directory
            if len(self.deleted_files[base_directory]) >= self.deletion_threshold:
                # Notify for the base directory
                self.generate_alert(base_directory)

                # Clear the list for the directory to avoid duplicate notifications
                self.deleted_files[base_directory].clear()



    def generate_alert(self, base_directory):
        self.title = 'EDR: "BULK FILE DELETION DETECTED"'
        self.msg = f"! More than {self.deletion_threshold} files were deleted in '{base_directory}'."
        alert = DesktopAlert(title=self.title, msg=self.msg)
        alert.show_alert()


def monitor_directories(paths, excluded_paths):
    event_handler = FileDeletionHandler(excluded_paths)
    observer = Observer()

    for path in paths:
        if os.path.exists(path):
            observer.schedule(event_handler, path, recursive=True)
        else:
            print(f"Path does not exist: {path}")

    observer.start()
    print(f"Monitoring directories: {', '.join(paths)}")
    try:
        while True:
            pass  # Keep the script running
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    # Get the user's profile directory
    user_profile = os.environ.get("USERPROFILE", "C:\\Users\\Default")

    # List of directories to monitor
    paths = [
        "C:\\",  # Root of C: drive
        os.path.join(user_profile, "Desktop"),
        os.path.join(user_profile, "Downloads"),
        os.path.join(user_profile, "Documents"),
    ]

    # List of directories to exclude from monitoring
    excluded_paths = [
        os.path.join(user_profile, "AppData"),  # Common cache and temporary storage directory
        "C:\\Windows\\Temp",                    # Temporary files directory
        "C:\\ProgramData",                      # System data
    ]

    monitor_directories(paths, excluded_paths)
    