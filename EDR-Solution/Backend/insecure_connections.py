import psutil
import requests
import time
from Backend.desktop_alert import DesktopAlert

class InsecureConnections:

    def __init__(self):
        self.VIRUSTOTAL_API_KEY = 'your_virustotal_api_key'  # Replace with your actual API key
        self.checked_ips = set()

    def get_active_connections(self):
        """Returns a list of unique IP addresses the system is connected to."""
        connections = psutil.net_connections(kind='inet')
        ips = set()
        for conn in connections:
            if conn.raddr:
                ips.add(conn.raddr.ip)
        return ips

    def check_ip_reputation(self, ip):
        """Checks the IP reputation using the VirusTotal API."""
        url = f'https://www.virustotal.com/vtapi/v2/ip-address/report'
        params = {
            'apikey': self.VIRUSTOTAL_API_KEY,
            'ip': ip
        }
        try:
            response = requests.get(url, params=params)
            if response.status_code == 200:
                data = response.json()
                # Check for positive detections from VirusTotal
                if 'response_code' in data and data['response_code'] == 1:
                    if 'detected_downloaded_samples' in data or 'detected_urls' in data:
                        return True  # IP is considered malicious
                    elif 'positives' in data and data['positives'] > 0:
                        return True
            return False  # IP is clean
        except Exception as e:
            print(f"Error checking IP reputation: {e}")
            return False

    def generate_alert(self, ip):
        """Generates a desktop alert for malicious IP detection."""
        title = 'EDR: Insecure Connection Detected'
        msg = f"Malicious IP Address Detected: {ip}"
        alert = DesktopAlert(title=title, msg=msg, severity="High")
        alert.show_alert()

    def monitor_insecure_connections(self):
        """Continuously monitors and checks IP connections."""
        while True:
            active_ips = self.get_active_connections()
            print(f"Active IPs: {', '.join(active_ips)}")  # Print all active IPs after each scan
            for ip in active_ips:
                if ip not in self.checked_ips:
                    print(f"Checking IP reputation for: {ip}")
                    if self.check_ip_reputation(ip):
                        self.generate_alert(ip)
                    self.checked_ips.add(ip)  # Mark IP as checked (clean or malicious)
            time.sleep(60)  # Check every 60 seconds


# Start Execution
# if __name__ == '__main__':
#     ic = InsecureConnections()
#     ic.monitor_insecure_connections()
