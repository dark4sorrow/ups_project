from flask import Flask, jsonify
import threading
import time
import subprocess
import shutil
import socket

app = Flask(__name__)

# --- CONFIGURATION ---
PORT = 5001
COMMUNITY_STRING = 's1lentb0b'
POLL_INTERVAL = 30  # Seconds

# Device Inventory
UPS_NAME_MAPPING = {
    "10.1.9.224": "Boswell MDF",
    "10.1.9.239": "Children's Center MDF",
    "10.1.9.248": "DARM MDF",
    "10.1.9.249": "DARM IDF",
    "10.1.9.212": "FSOQ MDF",
    "10.1.9.250": "FSOQ2 MDF",
    "10.1.9.233": "GYM MDF",
    "10.1.9.234": "GYM IDF B",
    "10.1.9.215": "Hedlund MDF",
    "10.1.9.242": "Hedlund IDF B",
    "10.1.9.221": "HSB MDF",
    "10.1.9.222": "HSB IDF",
    "10.1.9.228": "HSB IDF2",
    "10.1.9.213": "IAB MDF",
    "10.1.9.227": "HWC A MDF",
    "10.1.9.245": "HWC HR",
    "10.1.9.244": "HWC-C Maint",
    "10.1.9.217": "HWC Security",
    "10.1.9.237": "HWC E",
    "10.1.9.218": "Kildow MDF",
    "10.1.9.238": "Kildow IDF",
    "10.1.9.209": "Lee Hall 212",
    "10.1.9.208": "Lee Hall MDF",
    "10.1.9.240": "McLain Hall MDF",
    "10.1.9.214": "Molstead MDF",
    "10.1.9.241": "Molstead IDF B",
    "10.1.9.243": "Molstead IDF D",
    "10.1.9.211": "Post Hall MDF",
    "10.1.9.246": "Residence Hall",
    "10.3.9.213": "Sandpoint ANX",
    "10.1.9.230": "Seiter MDF",
    "10.1.9.231": "Seiter IDF B",
    "10.1.9.232": "Seiter IDF C",
    "10.1.9.223": "Sherman MDF",
    "10.1.9.254": "Siebert MDF",
    "10.1.9.253": "Siebert IDF",
    "10.1.9.220": "SUB MDF",
    "10.1.9.219": "SUB IDF B",
    "10.1.9.210": "SUB IDF C",
    "10.1.9.216": "SUB IDF D",
    "10.1.9.247": "Wellness Center MDF",
    "10.1.9.226": "Winton MDF",
    "10.102.0.100": "AAoA",
    "10.9.9.42": "CTE MDF",
    "10.9.9.43": "CTE IDF A",
    "10.9.9.44": "CTE IDF B",
    "10.101.0.200": "Head Start",
    "10.8.1.157": "POST ACADEMY MDF",
    "10.3.9.212": "Sandpoint IDF",
    "10.2.9.13": "WFT MDF2"
}

OID_ORDER = [
    "1.3.6.1.4.1.318.1.1.1.1.1.1.0", # 0: Model
    "1.3.6.1.4.1.318.1.1.1.4.1.1.0", # 1: Status
    "1.3.6.1.4.1.318.1.1.1.2.2.1.0", # 2: Battery Capacity
    "1.3.6.1.4.1.318.1.1.1.3.2.1.0", # 3: Input Voltage
    "1.3.6.1.4.1.318.1.1.1.4.2.1.0", # 4: Output Voltage
    "1.3.6.1.4.1.318.1.1.1.4.2.3.0", # 5: Load
    "1.3.6.1.4.1.318.1.1.1.7.2.3.0", # 6: Last Self Test
    "1.3.6.1.4.1.318.1.1.1.2.2.3.0", # 7: Runtime
    "1.3.6.1.4.1.318.1.1.1.2.1.1.0"  # 8: Battery Date
]

DETAILED_STATUS_MAP = {
    4: "Smart Boost", 5: "Smart Trim", 6: "Software Bypass",
    7: "Output Off", 8: "Rebooting", 9: "Switched Bypass", 10: "Hardware Failure"
}

ups_data_cache = {}
protocol_cache = {} # Stores IP -> 'http' or 'https'

def detect_protocol(ip):
    """Probes Port 443 to see if the device supports HTTPS"""
    if ip in protocol_cache:
        return protocol_cache[ip]
        
    try:
        # Try to connect to port 443 with a short timeout (0.5s)
        # If it accepts the connection, it supports HTTPS
        with socket.create_connection((ip, 443), timeout=0.5):
            protocol_cache[ip] = "https"
            return "https"
    except (socket.timeout, ConnectionRefusedError, OSError):
        # Connection failed, assume HTTP
        protocol_cache[ip] = "http"
        return "http"

def get_snmp_data(ip, name):
    result_data = {
        "ipAddress": ip, "name": name, "status": "Offline",
        "model": "N/A", "batteryCapacity": "0", "inputVoltage": "0",
        "outputVoltage": "0", "load": "0", "lastTestDate": "N/A",
        "runtime": "N/A", "batteryDate": "N/A",
        "statusClass": "status-offline",
        "protocol": "http"
    }

    try:
        # Determine Protocol (Happens in parallel with SNMP via threads)
        result_data["protocol"] = detect_protocol(ip)

        cmd = ["snmpget", "-v1", "-c", COMMUNITY_STRING, "-Oqv", ip] + OID_ORDER
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=2.5)

        if proc.returncode != 0:
            return result_data

        lines = proc.stdout.strip().split('\n')
        if len(lines) < 9: return result_data

        raw_model = lines[0].strip('"')
        raw_status = int(lines[1])

        if raw_status == 2 or raw_status == 1:
            result_data["status"] = "Online"
            result_data["statusClass"] = "status-online"
        elif raw_status == 3:
            result_data["status"] = "On Battery"
            result_data["statusClass"] = "status-on-battery"
        elif raw_status in DETAILED_STATUS_MAP:
            result_data["status"] = DETAILED_STATUS_MAP[raw_status]
            result_data["statusClass"] = "status-needs-attention"
        else:
            result_data["status"] = f"Code {raw_status}"
            result_data["statusClass"] = "status-needs-attention"

        result_data["model"] = raw_model
        result_data["batteryCapacity"] = lines[2].strip('"')
        result_data["inputVoltage"] = lines[3].strip('"')
        result_data["outputVoltage"] = lines[4].strip('"')
        result_data["load"] = lines[5].strip('"')
        result_data["lastTestDate"] = lines[6].strip('"')
        result_data["runtime"] = lines[7].strip('"')
        result_data["batteryDate"] = lines[8].strip('"')

        return result_data

    except Exception as e:
        print(f"Exception polling {ip}: {e}")
        return result_data

def poll_all_devices():
    print(f"Starting polling cycle for {len(UPS_NAME_MAPPING)} devices...")
    while True:
        threads = []
        for ip, name in UPS_NAME_MAPPING.items():
            t = threading.Thread(target=lambda i=ip, n=name: ups_data_cache.update({i: get_snmp_data(i, n)}))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        print("Polling cycle complete. Waiting...")
        time.sleep(POLL_INTERVAL)

@app.route('/api/ups-status', methods=['GET'])
def get_status():
    return jsonify(list(ups_data_cache.values()))

if __name__ == '__main__':
    if not shutil.which("snmpget"):
        print("CRITICAL ERROR: 'snmpget' command not found.")
        exit(1)

    poller_thread = threading.Thread(target=poll_all_devices, daemon=True)
    poller_thread.start()
    app.run(host='127.0.0.1', port=PORT, debug=False)
