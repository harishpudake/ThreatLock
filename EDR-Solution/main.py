from flask import Flask, request, jsonify, render_template
import hashlib
import csv
import os
import requests
import threading
from Backend.BulkFileDeletion import monitor_directories
from Backend.insecure_connections import InsecureConnections
from Backend.monitor_cpu_spike import MonitorCpuSpike
from Backend.MonitorLogFile import start_monitoring


app = Flask(__name__)

VIRUSTOTAL_API_KEY = "2edbf4bf785175c1e8f4cd4cfa98f87c6ec2c57c449bc41d2fb4f141765cfb43"
CSV_FILE_PATH = os.path.join(os.getcwd(), 'alert_history.csv')


# Function to read alerts from the CSV file
def read_alerts():
    alerts = []
    try:
        with open(CSV_FILE_PATH, 'r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                alerts.append(row)
    except FileNotFoundError:
        print(f"Warning: {CSV_FILE_PATH} not found.")
    return alerts


@app.route('/')
def home():
    return render_template('index.html')


#### FOR SCAN_URL ####
@app.route("/scan_url", methods=["POST"])
def scan_url():
    data = request.json
    url = data.get("url")

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    params = {"url": url}
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=params)

    if response.status_code == 200:
        result = response.json()
        analysis_id = result["data"]["id"]

        analysis_response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
        if analysis_response.status_code == 200:
            analysis_result = analysis_response.json()
            stats = analysis_result["data"]["attributes"]["stats"]
            malicious_count = stats["malicious"]
            
            return jsonify({"status": "malicious" if malicious_count > 0 else "safe"})

    return jsonify({"status": "error"})


#### FOR SCAN_FILE ####
def calculate_md5(file_path):
    try:
        with open(file_path, "rb") as f:
            file_hash = hashlib.md5()
            while chunk := f.read(8192):
                file_hash.update(chunk)
        return file_hash.hexdigest()
    except Exception as e:
        print(f"Error calculating MD5: {e}")
        return None


@app.route('/scan_file', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file uploaded'})

    file = request.files['file']

    # Save the file temporarily
    file_path = os.path.join('uploads', file.filename)
    os.makedirs('uploads', exist_ok=True)
    file.save(file_path)

    # Calculate the MD5 hash of the file
    file_hash = calculate_md5(file_path)

    if not file_hash:
        return jsonify({'status': 'error', 'message': 'Could not calculate file hash'})

    # Check the hash with VirusTotal
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    response = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers)

    # Delete the temporary file
    os.remove(file_path)

    if response.status_code == 200:
        result = response.json()
        malicious = result["data"]["attributes"]["last_analysis_stats"]["malicious"]
        return jsonify({"status": "malicious" if malicious > 0 else "safe"})

    return jsonify({'status': 'error', 'message': 'Unable to fetch data from VirusTotal'})


@app.route('/fetch-alerts', methods=['GET'])
def fetch_alerts():
    alerts = read_alerts()
    return jsonify(alerts)


@app.route('/alert-history')
def page1():
    return render_template('alert_history.html')

@app.route('/url-scan')
def page2():
    return render_template('scan_url.html')

@app.route('/file-scan')
def page3():
    return render_template('scan_file.html')

@app.route('/attack-info')
def page4():
    return render_template('info.html')

@app.route('/about-us')
def page5():
    return render_template('about_us.html')


### 🔹 MULTITHREADING FUNCTION TO RUN ALL MODULES ###
def start_monitoring_modules():
    # Start monitoring file deletions in critical directories
    user_profile = os.environ.get("USERPROFILE", "C:\\Users\\Default")
    paths = [
        "C:\\",
        os.path.join(user_profile, "Desktop"),
        os.path.join(user_profile, "Downloads"),
        os.path.join(user_profile, "Documents"),
    ]
    excluded_paths = [
        os.path.join(user_profile, "AppData"),
        "C:\\Windows\\Temp",
        "C:\\ProgramData",
    ]
    t1 = threading.Thread(target=monitor_directories, args=(paths, excluded_paths), daemon=True)

    # Start monitoring insecure network connections
    insecure_conn = InsecureConnections()
    t2 = threading.Thread(target=insecure_conn.monitor_insecure_connections, daemon=True)

    # Start monitoring high CPU spikes
    cpu_monitor = MonitorCpuSpike()
    t3 = threading.Thread(target=cpu_monitor.monitor_cpu_usage, daemon=True)

    # Start monitoring log file deletions
    LOGS_DIR = r"C:\Windows\System32\winevt\Logs"
    t4 = threading.Thread(target=start_monitoring, args=(LOGS_DIR,), daemon=True)

    # Start all threads
    t1.start()
    t2.start()
    t3.start()
    t4.start()


# Start Flask app and monitoring modules in separate threads
if __name__ == "__main__":
    # Start monitoring modules
    start_monitoring_modules()

    # Run Flask server (Main thread)
    app.run(debug=True)
