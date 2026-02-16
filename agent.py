import psutil
import time
from datetime import datetime
import socket
import uuid
import winreg
from scapy.all import sniff, IP, DNS, UDP
import ipinfo
from urllib.parse import quote
from pymongo import MongoClient
from threading import Thread, Lock
from queue import Queue
import platform
import logging
import win32evtlog
import win32con
import win32security
import win32api
import ctypes
import sys
import requests
from PIL import ImageGrab
import os
import virustotal_python
import sqlite3
import json
import traceback
from collections import Counter
import hashlib

# Setup detailed logging
logging.basicConfig(
    filename="agent.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filemode="a"
)
logger = logging.getLogger()

# Check and elevate to admin
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception as e:
        logger.error(f"Error checking admin status: {e}")
        return False

if not is_admin():
    logger.info("Elevating to Administrator privileges...")
    print("Elevating to Administrator privileges...")
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit(0)
    except Exception as e:
        logger.error(f"Failed to elevate privileges: {e}")
        print("Failed to elevate privileges. Please run manually as Administrator.")
        sys.exit(1)

# Ensure Windows-only
if platform.system() != "Windows":
    logger.error("This agent is designed for Windows only.")
    print("This agent is designed for Windows only.")
    sys.exit(1)

# MongoDB connection
DB_PASSWORD = "Hacker@66202"
ENCODED_PASSWORD = quote(DB_PASSWORD)
MONGO_URI = f"mongodb+srv://zyraadmin:{ENCODED_PASSWORD}@zyrasiemcluster.8ydms.mongodb.net/?retryWrites=true&w=majority&appName=ZyraSiemCluster"

mongo_client = None
db = None
device_collection = None
logs_collection = None
alerts_collection = None

def initialize_mongo():
    global mongo_client, db, device_collection, logs_collection, alerts_collection
    try:
        mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=10000)
        db = mongo_client["zyra_siem"]
        device_collection = db["device_info"]
        logs_collection = db["logs"]
        alerts_collection = db["alerts"]
        logger.info("Connected to MongoDB successfully")
        print("Connected to MongoDB successfully")
    except Exception as e:
        logger.error(f"Failed to connect to MongoDB: {e}\n{traceback.format_exc()}")
        print("Failed to connect to MongoDB. Using local storage until connection is restored.")

initialize_mongo()

# API endpoints
API_SERVER_URL = "http://localhost:5000"  # API server running on port 5000
VT_API_KEY_URL = f"{API_SERVER_URL}/get_vt_api_key"
COMMAND_URL = f"{API_SERVER_URL}/command"

# SQLite local storage setup
LOCAL_DB_FILE = "local_storage.db"
def init_local_db():
    try:
        conn = sqlite3.connect(LOCAL_DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS logs
                          (id INTEGER PRIMARY KEY AUTOINCREMENT, data TEXT)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS alerts
                          (id INTEGER PRIMARY KEY AUTOINCREMENT, data TEXT)''')
        conn.commit()
        conn.close()
        logger.info("Local SQLite database initialized")
    except Exception as e:
        logger.error(f"Error initializing local SQLite DB: {e}\n{traceback.format_exc()}")

init_local_db()

# Fetch VirusTotal API key
def fetch_vt_api_key():
    try:
        response = requests.get(VT_API_KEY_URL, timeout=5)
        if response.status_code == 200:
            api_key = response.json().get("api_key")
            logger.info("VirusTotal API key fetched successfully")
            return api_key
        logger.warning(f"Failed to fetch VT API key: {response.status_code}")
    except Exception as e:
        logger.error(f"Error fetching VT API key: {e}\n{traceback.format_exc()}")
    return None

VT_API_KEY = fetch_vt_api_key()
vt_client = virustotal_python.Virustotal(VT_API_KEY) if VT_API_KEY else None

# ipinfo.io setup
IPINFO_TOKEN = "2a9abeea1106f8"
ipinfo_handler = ipinfo.getHandler(IPINFO_TOKEN)

# Queues and locks
dns_queue = Queue()
network_queue = Queue()
log_queue = Queue()
alert_queue = Queue()
registry_changes = []
registry_lock = Lock()

# Hostname and persistent AGENT_ID
HOSTNAME = socket.gethostname()

def get_machine_guid():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography")
        guid, _ = winreg.QueryValueEx(key, "MachineGuid")
        winreg.CloseKey(key)
        return guid
    except Exception as e:
        logger.error(f"Error retrieving MachineGuid: {e}\n{traceback.format_exc()}")
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, HOSTNAME))

AGENT_ID = get_machine_guid()

# Real-time monitoring threads
stop_threads = False

def collect_system_metrics实时():
    while not stop_threads:
        try:
            metrics = {
                "cpu_percent": psutil.cpu_percent(interval=1),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_usage": psutil.disk_usage("C:\\").percent,
                "timestamp": datetime.now().isoformat(),
                "agent_id": AGENT_ID,
                "hostname": HOSTNAME
            }
            log_queue.put(("system_metrics", metrics))
            logger.info("System metrics collected")
            time.sleep(5)
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}\n{traceback.format_exc()}")
            time.sleep(5)

def get_system_logs实时():
    while not stop_threads:
        try:
            hand = win32evtlog.OpenEventLog(None, "System")
            total_records = win32evtlog.GetNumberOfEventLogRecords(hand)
            events = win32evtlog.ReadEventLog(hand, win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, 0)
            system_logs = []
            for event in events[:10]:
                if event.EventID == 4663:
                    system_logs.append({
                        "event_id": event.EventID,
                        "time": event.TimeGenerated.strftime("%Y-%m-%d %H:%M:%S"),
                        "desc": event.StringInserts[0] if event.StringInserts else "File deletion detected"
                    })
            if system_logs:
                log_queue.put(("system_logs", system_logs))
            win32evtlog.CloseEventLog(hand)
            logger.info("System logs collected")
            time.sleep(5)
        except Exception as e:
            logger.error(f"Error collecting system logs: {e}\n{traceback.format_exc()}")
            time.sleep(5)

def get_security_logs实时():
    failed_login_count = Counter()
    while not stop_threads:
        try:
            hProcess = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, False, win32api.GetCurrentProcessId())
            hToken = win32security.OpenProcessToken(hProcess, win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY)
            priv_id = win32security.LookupPrivilegeValue(None, "SeSecurityPrivilege")
            win32security.AdjustTokenPrivileges(hToken, False, [(priv_id, win32con.SE_PRIVILEGE_ENABLED)])

            hand = win32evtlog.OpenEventLog(None, "Security")
            total_records = win32evtlog.GetNumberOfEventLogRecords(hand)
            events = win32evtlog.ReadEventLog(hand, win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, 0)
            security_logs = []
            for event in events[:10]:
                if event.EventID in [4624, 4625, 4672, 4663]:
                    desc = event.StringInserts[0] if event.StringInserts else f"Event {event.EventID}"
                    security_logs.append({
                        "event_id": event.EventID,
                        "time": event.TimeGenerated.strftime("%Y-%m-%d %H:%M:%S"),
                        "desc": desc
                    })
                    if event.EventID == 4625:
                        user = event.StringInserts[5] if len(event.StringInserts) > 5 else "Unknown"
                        failed_login_count[user] += 1
            if security_logs:
                log_queue.put(("security_logs", security_logs))
            win32evtlog.CloseEventLog(hand)
            logger.info("Security logs collected")
            
            for user, count in failed_login_count.items():
                if count > 5:
                    alert_queue.put({"type": "Multiple Failed Logins", "severity": "High", "details": f"{count} failed logins by {user}", "timestamp": datetime.now().isoformat()})
            time.sleep(5)
        except Exception as e:
            logger.error(f"Error collecting security logs: {e}\n{traceback.format_exc()}")
            time.sleep(5)

def monitor_processes_with_vt实时():
    scanned_hashes = set()
    while not stop_threads:
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'exe']):
                proc_info = {
                    "pid": proc.info['pid'],
                    "name": proc.info['name'],
                    "username": proc.info['username'],
                    "cpu_percent": proc.info['cpu_percent'],
                    "memory_percent": proc.info['memory_percent'],
                    "exe_path": proc.info['exe'],
                    "timestamp": datetime.now().isoformat()
                }
                processes.append(proc_info)
                
                if proc_info["exe_path"] and proc_info["exe_path"] not in scanned_hashes and vt_client:
                    try:
                        with open(proc_info["exe_path"], "rb") as f:
                            file_hash = hashlib.sha256(f.read()).hexdigest()
                        scanned_hashes.add(proc_info["exe_path"])
                        resp = vt_client.request(f"files/{file_hash}")
                        positives = resp.data["attributes"]["last_analysis_stats"]["malicious"]
                        if positives > 0:
                            alert_queue.put({
                                "type": "Malware Detected",
                                "severity": "High",
                                "details": f"{proc_info['name']} (PID: {proc_info['pid']}) detected as malware by {positives} engines",
                                "timestamp": datetime.now().isoformat()
                            })
                    except Exception as e:
                        logger.error(f"Error scanning {proc_info['exe_path']} with VirusTotal: {e}\n{traceback.format_exc()}")
            
            log_queue.put(("processes", processes))
            logger.info("Processes monitored with VirusTotal")
            time.sleep(5)
        except Exception as e:
            logger.error(f"Error monitoring processes: {e}\n{traceback.format_exc()}")
            time.sleep(5)

def monitor_registry实时():
    global registry_changes
    while not stop_threads:
        try:
            with registry_lock:
                key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                value_count, _, last_modified = winreg.QueryInfoKey(key)
                change = {"key": key_path, "value_count": value_count, "last_modified": str(last_modified)}
                if change not in registry_changes:
                    registry_changes.append(change)
                    logger.info(f"Registry change detected: {key_path}")
                    log_queue.put(("registry_changes", registry_changes[-5:]))
                winreg.CloseKey(key)
            time.sleep(1)
        except Exception as e:
            logger.error(f"Error monitoring registry: {e}\n{traceback.format_exc()}")
            time.sleep(1)

def capture_traffic实时():
    def packet_handler(packet):
        try:
            if packet.haslayer(DNS) and packet.haslayer(UDP) and packet[UDP].dport == 53:
                dns_query = packet[DNS].qd.qname.decode("utf-8", errors="ignore")
                dns_ip = packet[IP].dst
                dns_queue.put({"query": dns_query, "ip": dns_ip, "timestamp": datetime.now().isoformat()})

            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                if src_ip.startswith(("192.168", "10.", "172.")) or src_ip == "127.0.0.1":
                    network_queue.put(("outbound", dst_ip))
                else:
                    network_queue.put(("inbound", src_ip))
        except Exception as e:
            logger.error(f"Packet handling error: {e}\n{traceback.format_exc()}")

    try:
        sniff(prn=packet_handler, store=0)
        logger.info("Traffic capture started")
    except Exception as e:
        logger.error(f"Traffic sniffing error: {e}\n{traceback.format_exc()}")

def process_dns_data():
    dns_data = []
    while not dns_queue.empty():
        dns_entry = dns_queue.get()
        if dns_entry not in dns_data:
            dns_data.append(dns_entry)
    return dns_data

def process_network_data():
    network_data = {"inbound": [], "outbound": []}
    while not network_queue.empty():
        direction, ip = network_queue.get()
        if ip not in [entry["ip"] for entry in network_data[direction]]:
            location = get_ip_location(ip)
            network_data[direction].append({"ip": ip, **location})
    return network_data

def get_ip_location(ip):
    try:
        details = ipinfo_handler.getDetails(ip)
        return {
            "city": details.city if hasattr(details, "city") else "Unknown",
            "region": details.region if hasattr(details, "region") else "Unknown",
            "country": details.country if hasattr(details, "country") else "Unknown",
            "asn": details.org if hasattr(details, "org") else "Unknown"
        }
    except Exception as e:
        logger.error(f"ipinfo error for {ip}: {e}\n{traceback.format_exc()}")
        return {"error": str(e)}

def take_screenshot():
    try:
        screenshot = ImageGrab.grab()
        filename = f"screenshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        screenshot.save(filename)
        logger.info(f"Screenshot saved: {filename}")
        return filename
    except Exception as e:
        logger.error(f"Error taking screenshot: {e}\n{traceback.format_exc()}")
        return None

def kill_process(pid):
    try:
        process = psutil.Process(pid)
        process.terminate()
        logger.info(f"Process {pid} terminated")
        return True
    except Exception as e:
        logger.error(f"Error killing process {pid}: {e}\n{traceback.format_exc()}")
        return False

def handle_api_command():
    while not stop_threads:
        try:
            response = requests.get(COMMAND_URL, timeout=5)
            if response.status_code == 200:
                command = response.json()
                if command.get("action") == "screenshot":
                    filename = take_screenshot()
                    requests.post(COMMAND_URL + "/result", json={"agent_id": AGENT_ID, "result": filename})
                elif command.get("action") == "kill_process" and "pid" in command:
                    success = kill_process(command["pid"])
                    requests.post(COMMAND_URL + "/result", json={"agent_id": AGENT_ID, "result": success})
                elif command.get("action") == "list_processes":
                    processes = log_queue.queue[-1][1] if log_queue.queue else []
                    requests.post(COMMAND_URL + "/result", json={"agent_id": AGENT_ID, "result": processes})
                logger.info(f"API command handled: {command.get('action')}")
            else:
                logger.warning(f"API command fetch failed: {response.status_code}")
        except Exception as e:
            logger.error(f"Error handling API command: {e}\n{traceback.format_exc()}")
        time.sleep(5)

def detect_anomalies(metrics, dns_data, network_data, system_logs, security_logs, processes):
    alerts = []
    try:
        if metrics and metrics.get("cpu_percent", 0) > 90:
            alerts.append({"type": "High CPU", "severity": "High", "details": f"CPU at {metrics['cpu_percent']}%", "timestamp": datetime.now().isoformat()})
        
        if len(dns_data) > 50:
            alerts.append({"type": "Frequent DNS", "severity": "Medium", "details": f"{len(dns_data)} queries detected", "timestamp": datetime.now().isoformat()})
        
        for ip_data in network_data.get("outbound", []):
            if ip_data.get("country") == "Unknown":
                alerts.append({"type": "Unknown IP", "severity": "Medium", "details": f"Outbound to {ip_data['ip']}", "timestamp": datetime.now().isoformat()})
        
        for log in system_logs:
            if log["event_id"] == 4663:
                alerts.append({"type": "File Deletion", "severity": "High", "details": log["desc"], "timestamp": datetime.now().isoformat()})
        
        for log in security_logs:
            if log["event_id"] == 4624:
                hour = int(log["time"].split(" ")[1].split(":")[0])
                if 0 <= hour <= 6:
                    alerts.append({"type": "Unusual Login Time", "severity": "Medium", "details": f"Login at {log['time']}", "timestamp": datetime.now().isoformat()})
                else:
                    alerts.append({"type": "User Login", "severity": "Low", "details": log["desc"], "timestamp": datetime.now().isoformat()})
            elif log["event_id"] == 4625:
                alerts.append({"type": "Failed Login", "severity": "Medium", "details": log["desc"], "timestamp": datetime.now().isoformat()})
            elif log["event_id"] == 4672:
                alerts.append({"type": "Privilege Change", "severity": "Medium", "details": log["desc"], "timestamp": datetime.now().isoformat()})
        
        for proc in processes:
            if proc["cpu_percent"] > 50 or "cmd.exe" in proc["name"].lower():
                alerts.append({"type": "Suspicious Process", "severity": "Medium", "details": f"{proc['name']} (PID: {proc['pid']}) by {proc['username']}", "timestamp": datetime.now().isoformat()})
    except Exception as e:
        logger.error(f"Error in anomaly detection: {e}\n{traceback.format_exc()}")
    return alerts

def store_locally(data, table):
    try:
        conn = sqlite3.connect(LOCAL_DB_FILE)
        cursor = conn.cursor()
        cursor.execute(f"INSERT INTO {table} (data) VALUES (?)", (json.dumps(data),))
        conn.commit()
        conn.close()
        logger.info(f"Data stored locally in {table}")
    except Exception as e:
        logger.error(f"Error storing data locally in {table}: {e}\n{traceback.format_exc()}")

def sync_local_data():
    global db, logs_collection, alerts_collection
    for table, collection in [("logs", logs_collection), ("alerts", alerts_collection)]:
        try:
            conn = sqlite3.connect(LOCAL_DB_FILE)
            cursor = conn.cursor()
            cursor.execute(f"SELECT data FROM {table}")
            local_data = [json.loads(row[0]) for row in cursor.fetchall()]
            if local_data and db is not None:
                collection.insert_many(local_data)
                logger.info(f"Synced {len(local_data)} items from {table} to MongoDB")
                cursor.execute(f"DELETE FROM {table}")
                conn.commit()
                logger.info(f"Cleared local storage: {table}")
            conn.close()
        except Exception as e:
            logger.error(f"Error syncing local data from {table}: {e}\n{traceback.format_exc()}")

def check_connectivity():
    try:
        if mongo_client is not None:
            mongo_client.admin.command('ping')
            return True
        return False
    except Exception:
        return False

def store_data实时():
    global db, logs_collection, alerts_collection
    
    log_data = {
        "agent_id": AGENT_ID,
        "timestamp": datetime.now().isoformat(),
        "system_metrics": {},
        "dns_queries": [],
        "network": {"inbound": [], "outbound": []},
        "system_logs": [],
        "security_logs": [],
        "processes": [],
        "registry_changes": []
    }
    
    while not stop_threads:
        try:
            while not log_queue.empty():
                key, value = log_queue.get()
                log_data[key] = value
            
            dns_data = process_dns_data()
            network_data = process_network_data()
            if dns_data:
                log_data["dns_queries"] = dns_data
            if network_data["inbound"] or network_data["outbound"]:
                log_data["network"] = network_data
            
            alerts = []
            while not alert_queue.empty():
                alerts.append(alert_queue.get())
            
            detected_alerts = detect_anomalies(
                log_data["system_metrics"],
                log_data["dns_queries"],
                log_data["network"],
                log_data["system_logs"],
                log_data["security_logs"],
                log_data["processes"]
            )
            alerts.extend(detected_alerts)
            
            if check_connectivity():
                if db is not None:
                    logs_collection.insert_one(log_data.copy())
                    logger.info(f"Log stored for agent {AGENT_ID}")
                    print(f"Log stored for agent {AGENT_ID}")
                    if alerts:
                        alerts_collection.insert_many([{**alert, "agent_id": AGENT_ID} for alert in alerts])
                        logger.info(f"{len(alerts)} alerts stored")
                        print(f"{len(alerts)} alerts generated")
                    sync_local_data()
                else:
                    logger.warning("MongoDB connection lost. Reconnecting...")
                    try:
                        initialize_mongo()
                        if db is not None:
                            logger.info("Reconnected to MongoDB")
                        else:
                            raise Exception("Reconnection failed")
                    except Exception as e:
                        logger.error(f"Failed to reconnect to MongoDB: {e}\n{traceback.format_exc()}")
                        store_locally(log_data, "logs")
                        if alerts:
                            store_locally(alerts, "alerts")
            else:
                logger.warning("No internet/MongoDB connection. Storing locally.")
                store_locally(log_data, "logs")
                if alerts:
                    store_locally(alerts, "alerts")
        except Exception as e:
            logger.error(f"Error in store_data: {e}\n{traceback.format_exc()}")
            store_locally(log_data, "logs")
            if alerts:
                store_locally(alerts, "alerts")
        
        time.sleep(5)

def store_device_info():
    global db, device_collection
    try:
        device_data = {
            "agent_id": AGENT_ID,
            "hostname": HOSTNAME,
            "os": f"{platform.system()} {platform.release()}",
            "first_seen": datetime.now().isoformat(),
            "last_updated": datetime.now().isoformat()
        }
        if db is not None and check_connectivity():
            if not device_collection.find_one({"agent_id": AGENT_ID}):
                device_collection.insert_one(device_data)
                logger.info(f"Device info stored for {AGENT_ID}")
            else:
                device_collection.update_one(
                    {"agent_id": AGENT_ID},
                    {"$set": {"last_updated": datetime.now().isoformat()}}
                )
        else:
            store_locally(device_data, "logs")
    except Exception as e:
        logger.error(f"Error storing device info: {e}\n{traceback.format_exc()}")
        store_locally(device_data, "logs")

if __name__ == "__main__":
    store_device_info()

    threads = [
        Thread(target=collect_system_metrics实时),
        Thread(target=get_system_logs实时),
        Thread(target=get_security_logs实时),
        Thread(target=monitor_processes_with_vt实时),
        Thread(target=monitor_registry实时),
        Thread(target=capture_traffic实时),
        Thread(target=handle_api_command),
        Thread(target=store_data实时)
    ]

    for t in threads:
        t.daemon = True
        t.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Agent stopped by user")
        print("Agent stopped by user")
        stop_threads = True
        for t in threads:
            t.join(timeout=5)