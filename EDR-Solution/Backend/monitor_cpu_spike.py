import psutil
import time
from Backend.desktop_alert import DesktopAlert


class MonitorCpuSpike():

    def __init__(self):
        self.CPU_THRESHOLD = 3.0
        

    def set_cpu_threshold(self, val):
        self.CPU_THRESHOLD = val


    def generate_alert(self, processes):
        title = 'EDR: "High CPU usages detected"'
        msg = "Top CPU Consuming Processes:\n"
        for proc in processes:
            msg += f"! Name: {proc['name']} (PID: {proc['pid']})\n"
        alert = DesktopAlert(title=title, msg=msg, severity="Low")
        alert.show_alert()
        

    def get_top_processes(self):
        all_processes = []
        # Using 'pid', 'name', 'cpu_percent' for each process in a more optimized way
        for process in psutil.process_iter(['pid', 'name', 'cpu_percent']):
            try:
                all_processes.append(process.info)
            except:
                continue
        # Sort and get top 10 processes with the highest CPU usage
        top_processes = sorted(all_processes, key=lambda proc: proc['cpu_percent'], reverse=True)[:5]
        # Return only pid and name for each of the top 10 processes
        return [{'pid': proc['pid'], 'name': proc['name']} for proc in top_processes]


    def monitor_cpu_usage(self):
        # Initially measure CPU usage to avoid startup spike
        psutil.cpu_percent(interval=1)

        while True:
            current_cpu_usage = psutil.cpu_percent(interval=1)

            if current_cpu_usage >= self.CPU_THRESHOLD:
                top_process = self.get_top_processes()
                print(f"ALERT: HIGH CPU USAGE DETECTED! {current_cpu_usage}%")
                # Display only the top processes
                self.generate_alert(top_process)
                time.sleep(1200)  # Sleep for 20 minutes after alert
            time.sleep(2)  # Sleep for a short interval before the next check



# if __name__ == '__main__':
#     m = MonitorCpuSpike()
#     m.monitor_cpu_usage()
