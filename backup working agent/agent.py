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
from collections import Counter

# Check and elevate to admin
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    print("Elevating to Administrator privileges...")
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit(0)

# Ensure Windows-only
if platform.system() != "Windows":
    print("This agent is designed for Windows only.")
    exit(1)

# Setup local logging
logging.basicConfig(
    filename="agent.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger()

# MongoDB connection
DB_PASSWORD = "Hacker@66202"
ENCODED_PASSWORD = quote(DB_PASSWORD)
MONGO_URI = f"mongodb+srv://zyraadmin:{ENCODED_PASSWORD}@zyrasiemcluster.8ydms.mongodb.net/?retryWrites=true&w=majority&appName=ZyraSiemCluster"

try:
    mongo_client = MongoClient(MONGO_URI)
    db = mongo_client["zyra_siem"]
    device_collection = db["device_info"]
    logs_collection = db["logs"]
    alerts_collection = db["alerts"]
    logger.info("Connected to MongoDB successfully")
    print("Connected to MongoDB successfully")
except Exception as e:
    logger.error(f"Failed to connect to MongoDB: {e}")
    print(f"Failed to connect to MongoDB: {e}")
    exit(1)

# ipinfo.io setup
IPINFO_TOKEN = "2a9abeea1106f8"
ipinfo_handler = ipinfo.getHandler(IPINFO_TOKEN)

# API endpoint (replace with your actual API)
API_URL = "http://your-api-endpoint.localhost:5000/command"

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
    """Get persistent UUID from Windows MachineGuid."""
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography")
        guid, _ = winreg.QueryValueEx(key, "MachineGuid")
        winreg.CloseKey(key)
        return guid
    except Exception as e:
        logger.error(f"Error retrieving MachineGuid: {e}")
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, HOSTNAME))

AGENT_ID = get_machine_guid()

# Real-time monitoring threads
stop_threads = False

def collect_system_metrics实时():
    """Real-time system metrics collection."""
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
            logger.error(f"Error collecting system metrics: {e}")
            time.sleep(5)

def get_system_logs实时():
    """Real-time System logs collection."""
    while not stop_threads:
        try:
            hand = win32evtlog.OpenEventLog(None, "System")
            total_records = win32evtlog.GetNumberOfEventLogRecords(hand)
            events = win32evtlog.ReadEventLog(hand, win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, 0)
            system_logs = []
            for event in events[:10]:  # Last 10 events
                if event.EventID == 4663:  # File deletion
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
            logger.error(f"Error collecting system logs: {e}")
            time.sleep(5)  # Retry after delay

def get_security_logs实时():
    """Real-time Security logs collection with privilege adjustment."""
    failed_login_count = Counter()
    while not stop_threads:
        try:
            # Adjust privileges
            hProcess = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, False, win32api.GetCurrentProcessId())
            hToken = win32security.OpenProcessToken(hProcess, win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY)
            priv_id = win32security.LookupPrivilegeValue(None, "SeSecurityPrivilege")
            win32security.AdjustTokenPrivileges(hToken, False, [(priv_id, win32con.SE_PRIVILEGE_ENABLED)])

            hand = win32evtlog.OpenEventLog(None, "Security")
            total_records = win32evtlog.GetNumberOfEventLogRecords(hand)
            events = win32evtlog.ReadEventLog(hand, win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, 0)
            security_logs = []
            for event in events[:10]:
                if event.EventID in [4624, 4625, 4672, 4663]:  # Login success, failure, privilege, file deletion
                    desc = event.StringInserts[0] if event.StringInserts else f"Event {event.EventID}"
                    security_logs.append({
                        "event_id": event.EventID,
                        "time": event.TimeGenerated.strftime("%Y-%m-%d %H:%M:%S"),
                        "desc": desc
                    })
                    if event.EventID == 4625:  # Track failed logins
                        user = event.StringInserts[5] if len(event.StringInserts) > 5 else "Unknown"
                        failed_login_count[user] += 1
            if security_logs:
                log_queue.put(("security_logs", security_logs))
            win32evtlog.CloseEventLog(hand)
            logger.info("Security logs collected")
            
            # Check for suspicious login activity
            for user, count in failed_login_count.items():
                if count > 5:  # Threshold for failed logins
                    alert_queue.put({"type": "Multiple Failed Logins", "severity": "High", "details": f"{count} failed logins by {user}", "timestamp": datetime.now().isoformat()})
            time.sleep(5)
        except Exception as e:
            logger.error(f"Error collecting security logs: {e}")
            time.sleep(5)

def monitor_processes实时():
    """Real-time process monitoring."""
    while not stop_threads:
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
                processes.append({
                    "pid": proc.info['pid'],
                    "name": proc.info['name'],
                    "username": proc.info['username'],
                    "cpu_percent": proc.info['cpu_percent'],
                    "memory_percent": proc.info['memory_percent'],
                    "timestamp": datetime.now().isoformat()
                })
            log_queue.put(("processes", processes))
            logger.info("Processes monitored")
            time.sleep(5)
        except Exception as e:
            logger.error(f"Error monitoring processes: {e}")
            time.sleep(5)

def monitor_registry实时():
    """Real-time registry monitoring."""
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
            logger.error(f"Error monitoring registry: {e}")
            time.sleep(1)

def capture_traffic实时():
    """Real-time traffic capture."""
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
            logger.error(f"Packet handling error: {e}")

    try:
        sniff(prn=packet_handler, store=0)  # Continuous sniffing
        logger.info("Traffic capture started")
    except Exception as e:
        logger.error(f"Traffic sniffing error: {e}")

def process_dns_data():
    """Process DNS data."""
    dns_data = []
    while not dns_queue.empty():
        dns_entry = dns_queue.get()
        if dns_entry not in dns_data:
            dns_data.append(dns_entry)
    return dns_data

def process_network_data():
    """Process network data."""
    network_data = {"inbound": [], "outbound": []}
    while not network_queue.empty():
        direction, ip = network_queue.get()
        if ip not in [entry["ip"] for entry in network_data[direction]]:
            location = get_ip_location(ip)
            network_data[direction].append({"ip": ip, **location})
    return network_data

def get_ip_location(ip):
    """Get IP location."""
    try:
        details = ipinfo_handler.getDetails(ip)
        return {
            "city": details.city if hasattr(details, "city") else "Unknown",
            "region": details.region if hasattr(details, "region") else "Unknown",
            "country": details.country if hasattr(details, "country") else "Unknown",
            "asn": details.org if hasattr(details, "org") else "Unknown"
        }
    except Exception as e:
        logger.error(f"ipinfo error for {ip}: {e}")
        return {"error": str(e)}

def take_screenshot():
    """Take a screenshot."""
    try:
        screenshot = ImageGrab.grab()
        filename = f"screenshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        screenshot.save(filename)
        logger.info(f"Screenshot saved: {filename}")
        return filename
    except Exception as e:
        logger.error(f"Error taking screenshot: {e}")
        return None

def kill_process(pid):
    """Kill a process by PID."""
    try:
        process = psutil.Process(pid)
        process.terminate()
        logger.info(f"Process {pid} terminated")
        return True
    except Exception as e:
        logger.error(f"Error killing process {pid}: {e}")
        return False

def handle_api_command():
    """Handle API commands in real-time."""
    while not stop_threads:
        try:
            response = requests.get(API_URL, timeout=5)
            if response.status_code == 200:
                command = response.json()
                if command.get("action") == "screenshot":
                    filename = take_screenshot()
                    requests.post(API_URL + "/result", json={"agent_id": AGENT_ID, "result": filename})
                elif command.get("action") == "kill_process" and "pid" in command:
                    success = kill_process(command["pid"])
                    requests.post(API_URL + "/result", json={"agent_id": AGENT_ID, "result": success})
                elif command.get("action") == "list_processes":
                    processes = monitor_processes实时()  # Get latest processes
                    requests.post(API_URL + "/result", json={"agent_id": AGENT_ID, "result": processes[-1][1]})
        except Exception as e:
            logger.error(f"Error handling API command: {e}")
        time.sleep(5)

def detect_anomalies(metrics, dns_data, network_data, system_logs, security_logs, processes):
    """Real-time anomaly detection with login monitoring."""
    alerts = []
    
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
        if log["event_id"] == 4624:  # Successful login
            hour = int(log["time"].split(" ")[1].split(":")[0])
            if 0 <= hour <= 6:  # Unusual login time (e.g., midnight to 6 AM)
                alerts.append({"type": "Unusual Login Time", "severity": "Medium", "details": f"Login at {log['time']}", "timestamp": datetime.now().isoformat()})
            else:
                alerts.append({"type": "User Login", "severity": "Low", "details": log["desc"], "timestamp": datetime.now().isoformat()})
        elif log["event_id"] == 4625:  # Failed login
            alerts.append({"type": "Failed Login", "severity": "Medium", "details": log["desc"], "timestamp": datetime.now().isoformat()})
        elif log["event_id"] == 4672:
            alerts.append({"type": "Privilege Change", "severity": "Medium", "details": log["desc"], "timestamp": datetime.now().isoformat()})
    
    for proc in processes:
        if proc["cpu_percent"] > 50 or "cmd.exe" in proc["name"].lower():
            alerts.append({"type": "Suspicious Process", "severity": "Medium", "details": f"{proc['name']} (PID: {proc['pid']}) by {proc['username']}", "timestamp": datetime.now().isoformat()})
    
    return alerts

def store_data实时():
    """Real-time data storage."""
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
        # Process log queue
        while not log_queue.empty():
            key, value = log_queue.get()
            log_data[key] = value
        
        # Process DNS and network data
        dns_data = process_dns_data()
        network_data = process_network_data()
        if dns_data:
            log_data["dns_queries"] = dns_data
        if network_data["inbound"] or network_data["outbound"]:
            log_data["network"] = network_data
        
        # Process alerts from queue
        alerts = []
        while not alert_queue.empty():
            alerts.append(alert_queue.get())
        
        # Detect anomalies
        detected_alerts = detect_anomalies(
            log_data["system_metrics"],
            log_data["dns_queries"],
            log_data["network"],
            log_data["system_logs"],
            log_data["security_logs"],
            log_data["processes"]
        )
        alerts.extend(detected_alerts)
        
        # Store logs
        try:
            logs_collection.insert_one(log_data.copy())
            logger.info(f"Log stored for agent {AGENT_ID}")
            print(f"Log stored for agent {AGENT_ID}")
        except Exception as e:
            logger.error(f"Error storing log: {e}")
        
        # Store alerts
        if alerts:
            try:
                alerts_collection.insert_many([{**alert, "agent_id": AGENT_ID} for alert in alerts])
                logger.info(f"{len(alerts)} alerts stored")
                print(f"{len(alerts)} alerts generated")
            except Exception as e:
                logger.error(f"Error storing alerts: {e}")
        
        time.sleep(5)  # Batch updates every 5 seconds

def store_device_info():
    """Store or update device info."""
    try:
        device_data = {
            "agent_id": AGENT_ID,
            "hostname": HOSTNAME,
            "os": f"{platform.system()} {platform.release()}",
            "first_seen": datetime.now().isoformat(),
            "last_updated": datetime.now().isoformat()
        }
        if not device_collection.find_one({"agent_id": AGENT_ID}):
            device_collection.insert_one(device_data)
            logger.info(f"Device info stored for {AGENT_ID}")
        else:
            device_collection.update_one(
                {"agent_id": AGENT_ID},
                {"$set": {"last_updated": datetime.now().isoformat()}}
            )
    except Exception as e:
        logger.error(f"Error storing device info: {e}")

if __name__ == "__main__":
    store_device_info()

    # Start real-time monitoring threads
    threads = [
        Thread(target=collect_system_metrics实时),
        Thread(target=get_system_logs实时),
        Thread(target=get_security_logs实时),
        Thread(target=monitor_processes实时),
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
            time.sleep(1)  # Keep main thread alive
    except KeyboardInterrupt:
        logger.info("Agent stopped by user")
        print("Agent stopped by user")
        stop_threads = True
        for t in threads:
            t.join(timeout=5)