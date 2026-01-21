from flask import Flask, jsonify, request, render_template, redirect, url_for, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import threading
import time
import subprocess
import shutil
import socket
import psutil
import urllib.request
import requests
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET
import ssl
import nmap
import json
import os
from datetime import datetime
import logging
from functools import wraps

app = Flask(__name__)
app.secret_key = 'SUPER_SECRET_KEY_CHANGE_THIS_LOCALLY'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

USERS_FILE = 'users.json'
USERS = {}

def save_users():
    try:
        with open(USERS_FILE, 'w') as f:
            json.dump(USERS, f, indent=4)
    except Exception as e:
        print(f'Error saving users: {e}')

def load_users():
    global USERS
    try:
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, 'r') as f:
                USERS = json.load(f)
        else:
            print('WARNING: Users file not found. Starting with default.')
            USERS = {
                'admin': {'password': 'netsys', 'email': 'admin@netsys.com'},
                'choomba': {'password': 'password', 'email': 'choomba@netsys.com'}
            }
            save_users()
    except Exception as e:
        print(f'Error loading users: {e}')

load_users()

UPS_WEB_USER = 'apc'
UPS_WEB_PASS = 'apc'

# --- DYNAMIC INVENTORY SETUP ---
INVENTORY_FILE = 'ups_inventory.json'
UPS_NAME_MAPPING = {} # Will be populated from file

def load_inventory():
    global UPS_NAME_MAPPING
    try:
        if os.path.exists(INVENTORY_FILE):
            with open(INVENTORY_FILE, 'r') as f:
                UPS_NAME_MAPPING = json.load(f)
        else:
            print('WARNING: Inventory file not found. Starting with empty list.')
            UPS_NAME_MAPPING = {}
    except Exception as e:
        print(f'Error loading inventory: {e}')

def save_inventory():
    try:
        with open(INVENTORY_FILE, 'w') as f:
            json.dump(UPS_NAME_MAPPING, f, indent=4)
    except Exception as e:
        print(f'Error saving inventory: {e}')

# Load immediately on startup
load_inventory()

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    if user_id in USERS:
        return User(user_id)
    return None

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 'admin':
            return '<h1>Forbidden</h1>', 403
        return f(*args, **kwargs)
    return decorated_function

# --- HTML & AUTH ROUTES ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username in USERS and USERS[username]['password'] == password:
            login_user(User(username))
            return redirect(url_for('index'))
        return render_template('login.html', error='Invalid Credentials')
    return render_template('login.html')

@app.route('/')
@login_required
def index():
    return render_template('index.html', user=current_user)

@app.route('/ups_dashboard.html')
@login_required
def ups_dashboard():
    return render_template('ups_dashboard.html')

@app.route('/nmap_index.html')
@login_required
def nmap_dashboard():
    return render_template('nmap_index.html')

@app.route('/ssl_dashboard.html')
@login_required
def ssl_dashboard():
    return render_template('ssl_dashboard.html')

@app.route('/about.html')
@login_required
def about_page():
    return render_template('about.html')

@app.route('/borgui/')
@login_required
def borg_ui_proxy():
    return '', 200

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/auth_check')
def auth_check():
    if current_user.is_authenticated:
        return 'OK', 200
    else:
        return 'Unauthorized', 401

@app.route('/admin')
@login_required
@admin_required
def admin():
    load_users()
    return render_template('admin.html', users=USERS)

# --- USER MANAGEMENT ROUTES ---
@app.route('/admin/create_user', methods=['POST'])
@login_required
@admin_required
def create_user():
    load_users()
    username = request.form.get('username')
    password = request.form.get('password')
    email = request.form.get('email')
    if username and password and email:
        if username not in USERS:
            USERS[username] = {'password': password, 'email': email}
            save_users()
            return redirect(url_for('admin'))
    return 'Error creating user', 400

@app.route('/admin/delete_user/<username>')
@login_required
@admin_required
def delete_user(username):
    load_users()
    if username in USERS:
        if username != 'admin':
            del USERS[username]
            save_users()
    return redirect(url_for('admin'))

@app.route('/admin/edit_user/<username>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(username):
    load_users()
    if username in USERS:
        if request.method == 'POST':
            password = request.form.get('password')
            email = request.form.get('email')
            if password:
                USERS[username]['password'] = password
            if email:
                USERS[username]['email'] = email
            save_users()
            return redirect(url_for('admin'))
        return render_template('edit_user.html', username=username, user_data=USERS[username])
    return 'User not found', 404

# --- CONFIGURATION ---
PORT = 5001
COMMUNITY_STRING = 's1lentb0b'
POLL_INTERVAL_UPS = 30
POLL_INTERVAL_DOMAINS = 3600

SSL_DOMAINS = [
    'ADFS.nic.edu', 'IDM1.nic.edu', 'IDM2.nic.edu', 'IVCVideo.nic.edu', 'RDG2.nic.edu',
    'TIDM.nic.edu', 'av.nic.edu', 'aviso.nic.edu', 'bomgar.nic.edu', 'boulder.nic.edu',
    'br1.nic.edu', 'campusrec.nic.edu', 'campusweb.nic.edu', 'clconnect.nic.edu',
    'collui.nic.edu', 'coursecontent.nic.edu', 'dropbox.nic.edu', 'elk8-prod.nic.edu',
    'elk9-test.nic.edu', 'etcentral.nic.edu', 'etsts.nic.edu', 'expressway-edge.nic.edu',
    'ezproxy1.nic.edu', 'ftpsec.nic.edu', 'fusion.nic.edu', 'gve.nic.edu', 'hostheader.nic.edu',
    'icanhasvpn.nic.edu', 'idm.nic.edu', 'idmp.nic.edu', 'idp.nic.edu', 'infoblox.nic.edu',
    'ivc.nic.edu', 'learningspace.nic.edu', 'login.ezproxy1.nic.edu', 'mail2019.nic.edu',
    'mailr1.nic.edu', 'mailr2.nic.edu', 'mdc-vpngw-1.nic.edu', 'mobis.nic.edu',
    'mynic.nic.edu', 'mynic13.nic.edu', 'nic.edu', 'nicdc1.nic.edu', 'nicdc5.nic.edu',
    'nicns1.nic.edu', 'nicns2.nic.edu', 'niconline.nic.edu', 'nicstream.nic.edu',
    'nps-nac1.nic.edu', 'nps-nac2.nic.edu', 'nps.nic.edu', 'ns1.cite.nic.edu',
    'ns2.cite.nic.edu', 'olap.nic.edu', 'pbi.nic.edu', 'pcomm.nic.edu', 'prv.nic.edu',
    'rdg.nic.edu', 'sdc-t2019-dcc02.nic.edu', 'sdc-vpngw-1.nic.edu', 'sftp.nic.edu',
    'stars.nic.edu', 'tclconnect.nic.edu', 'tcollui.nic.edu', 'tcss.nic.edu',
    'testcomm.nic.edu', 'testetcentral.nic.edu', 'testmynic.nic.edu', 'touchnet.nic.edu',
    'tprv.nic.edu', 'ttouchnet.nic.edu', 'twebsvc.nic.edu', 'twebsvc2.nic.edu',
    'twebsvcfe.nic.edu', 'vcse.nic.edu', 'video.nic.edu', 'vidtest.nic.edu',
    'vpn.nic.edu', 'vpn2.nic.edu', 'web.nic.edu', 'webapps.nic.edu', 'webcon.nic.edu',
    'websvc.nic.edu', 'websvc2.nic.edu', 'websvcfe.nic.edu', 'ww2.nic.edu'
]

# UPDATED OID LIST: Added 'Identification Name' (1.3.6.1.4.1.318.1.1.1.1.1.2.0) at the START
OID_ORDER = [
    '1.3.6.1.4.1.318.1.1.1.1.1.2.0', # [0] UPS Ident Name (e.g. APC-SUB-MDF-ION)
    '1.3.6.1.4.1.318.1.1.1.1.1.1.0', # [1] Model
    '1.3.6.1.4.1.318.1.1.1.4.1.1.0', # [2] Status
    '1.3.6.1.4.1.318.1.1.1.2.2.1.0', # [3] Battery Capacity
    '1.3.6.1.4.1.318.1.1.1.3.2.1.0', # [4] Input Voltage
    '1.3.6.1.4.1.318.1.1.1.4.2.1.0', # [5] Output Voltage
    '1.3.6.1.4.1.318.1.1.1.4.2.3.0', # [6] Load
    '1.3.6.1.4.1.318.1.1.1.7.2.3.0', # [7] Last Test Date
    '1.3.6.1.4.1.318.1.1.1.2.2.3.0', # [8] Runtime
    '1.3.6.1.4.1.318.1.1.1.2.1.1.0', # [9] Battery Date
    '1.3.6.1.4.1.318.1.1.1.1.2.1.0', # [10] Firmware
    '1.3.6.1.4.1.318.1.1.1.1.2.3.0'  # [11] Serial Number
]

DETAILED_STATUS_MAP = {
    4: 'Smart Boost', 5: 'Smart Trim', 6: 'Software Bypass',
    7: 'Output Off', 8: 'Rebooting', 9: 'Switched Bypass', 10: 'Hardware Failure'
}

ups_data_cache = {}
protocol_cache = {}
domain_audit_cache = []

# --- HELPERS ---
def detect_protocol(ip):
    if ip in protocol_cache: return protocol_cache[ip]
    try:
        with socket.create_connection((ip, 443), timeout=0.5):
            protocol_cache[ip] = 'https'
            return 'https'
    except:
        protocol_cache[ip] = 'http'
        return 'http'

def analyze_headers(domain):
    issues = []
    headers_summary = {'hsts': False, 'xframe': False, 'server_leak': False}
    try:
        url = f'https://{domain}'
        req = urllib.request.Request(url, method='HEAD', headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=3) as response:
            headers = response.headers
            if 'Strict-Transport-Security' in headers: headers_summary['hsts'] = True
            else: issues.append('Missing HSTS')
            if 'X-Frame-Options' in headers: headers_summary['xframe'] = True
            else: issues.append('Missing X-Frame-Options')
            srv = headers.get('Server', '')
            if any(char.isdigit() for char in srv):
                headers_summary['server_leak'] = True
                issues.append(f'Server Leak: {srv}')
    except Exception:
        issues.append('Header Scan Failed')
    return headers_summary, issues

def audit_single_domain(domain):
    result = {'domain': domain, 'days_remaining': -1, 'expiry_date': 'Unknown', 'ssl_status': 'Error', 'issues': [], 'grade': 'F'}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                not_after = cert['notAfter']
                expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                days_remaining = (expiry_date - datetime.utcnow()).days
                result['expiry_date'] = expiry_date.strftime('%Y-%m-%d')
                result['days_remaining'] = days_remaining
                if days_remaining < 7: result['ssl_status'] = 'Critical'
                elif days_remaining < 30: result['ssl_status'] = 'Warning'
                else: result['ssl_status'] = 'Good'
        headers, header_issues = analyze_headers(domain)
        result['issues'] = header_issues
        if result['ssl_status'] != 'Good': result['grade'] = 'F'
        elif not headers['hsts']: result['grade'] = 'C'
        elif headers['server_leak']: result['grade'] = 'B'
        else: result['grade'] = 'A'
    except Exception as e:
        result['expiry_date'] = 'Conn Error'
        result['grade'] = 'X'
    return result

def poll_ups_devices():
    last_inventory_mtime = 0
    while True:
        try:
            if os.path.exists(INVENTORY_FILE):
                mtime = os.path.getmtime(INVENTORY_FILE)
                if mtime > last_inventory_mtime:
                    load_inventory()
                    last_inventory_mtime = mtime
        except Exception as e:
            print(f"Error checking inventory update: {e}")

        # Create a snapshot of current mapping to iterate safely
        current_map = UPS_NAME_MAPPING.copy()
        
        # Remove deleted items from cache
        cache_ips = list(ups_data_cache.keys())
        for ip in cache_ips:
            if ip not in current_map:
                del ups_data_cache[ip]

        threads = []
        for ip, name in current_map.items():
            t = threading.Thread(target=lambda i=ip, n=name: ups_data_cache.update({i: get_snmp_data(i, n)}))
            threads.append(t)
            t.start()
        for t in threads: t.join()
        time.sleep(POLL_INTERVAL_UPS)

def poll_domains():
    global domain_audit_cache
    while True:
        results = []
        for domain in SSL_DOMAINS:
            results.append(audit_single_domain(domain))
        results.sort(key=lambda x: (x['grade'], x['days_remaining']))
        domain_audit_cache = results
        time.sleep(POLL_INTERVAL_DOMAINS)

def get_snmp_data(ip, default_name):
    # Default values
    res = {
        'ipAddress': ip, 
        'name': default_name, 
        'status': 'Offline', 
        'model': 'N/A', 
        'firmware': 'N/A',
        'batteryCapacity': '0', 
        'inputVoltage': '0', 
        'outputVoltage': '0', 
        'load': '0', 
        'lastTestDate': 'N/A', 
        'runtime': 'N/A', 
        'batteryDate': 'N/A', 
        'statusClass': 'status-offline', 
        'protocol': 'http', 
        'serialNumber': 'N/A',
        'batteryType': 'Lead-Acid' # Default
    }
    
    try:
        res['protocol'] = detect_protocol(ip)
        cmd = ['snmpget', '-v1', '-c', COMMUNITY_STRING, '-Oqv', ip] + OID_ORDER
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=2.5)
        
        if proc.returncode != 0: return res
        
        lines = proc.stdout.strip().split('\n')
        # Check if we have enough lines (now 12 lines expected due to added OID)
        if len(lines) < 12: return res
        
        # [0] is now the fetched UPS Identification Name
        fetched_name = lines[0].strip('"')
        
        # Use fetched name if valid, otherwise keep default
        final_name = fetched_name if fetched_name and fetched_name != 'No Such Object' else default_name
        
        # Determine Battery Type based on FINAL NAME (from SNMP if available)
        if final_name.strip().upper().endswith('ION'):
            batt_type = 'Li-Ion'
        else:
            batt_type = 'Lead-Acid'
            
        res['name'] = final_name
        res['batteryType'] = batt_type
        
        raw_status = int(lines[2]) # [2] is Status
        if raw_status in [1, 2]: res.update({'status': 'Online', 'statusClass': 'status-online'})
        elif raw_status == 3: res.update({'status': 'On Battery', 'statusClass': 'status-on-battery'})
        elif raw_status in DETAILED_STATUS_MAP: res.update({'status': DETAILED_STATUS_MAP[raw_status], 'statusClass': 'status-needs-attention'})
        else: res.update({'status': f'Code {raw_status}', 'statusClass': 'status-needs-attention'})

        res.update({
            'model': lines[1].strip('"'), # [1] Model
            'batteryCapacity': lines[3].strip('"'), # [3] Capacity
            'inputVoltage': lines[4].strip('"'), # [4] Input V
            'outputVoltage': lines[5].strip('"'), # [5] Output V
            'load': lines[6].strip('"'), # [6] Load
            'lastTestDate': lines[7].strip('"'), # [7] Test Date
            'runtime': lines[8].strip('"'), # [8] Runtime
            'batteryDate': lines[9].strip('"'), # [9] Batt Date
            'firmware': lines[10].strip('"'), # [10] Firmware
            'serialNumber': lines[11].strip('"') # [11] Serial
        })
        return res
    except: return res

# --- API ENDPOINTS ---

@app.route('/api/ups-status', methods=['GET'])
@login_required
def get_status(): return jsonify(list(ups_data_cache.values()))

# NEW: Inventory Management Routes

@app.route('/api/ups/add', methods=['POST'])
@login_required
@admin_required
def add_ups():
    data = request.json
    ip = data.get('ip')
    name = data.get('name')
    if not ip or not name:
        return jsonify({'error': 'Missing IP or Name'}), 400
    if ip in UPS_NAME_MAPPING:
        return jsonify({'error': 'IP already exists'}), 400
    
    UPS_NAME_MAPPING[ip] = name
    save_inventory()
    # Trigger immediate poll for new device in background
    threading.Thread(target=lambda: ups_data_cache.update({ip: get_snmp_data(ip, name)})).start()
    return jsonify({'success': True})

@app.route('/api/ups/delete', methods=['POST'])
@login_required
@admin_required
def delete_ups():
    data = request.json
    ip = data.get('ip')
    if ip in UPS_NAME_MAPPING:
        del UPS_NAME_MAPPING[ip]
        if ip in ups_data_cache:
            del ups_data_cache[ip]
        save_inventory()
        return jsonify({'success': True})
    return jsonify({'error': 'Device not found'}), 404

@app.route('/api/ups/edit', methods=['POST'])
@login_required
@admin_required
def edit_ups():
    data = request.json
    old_ip = data.get('old_ip')
    new_ip = data.get('new_ip')
    new_name = data.get('new_name')
    
    if old_ip not in UPS_NAME_MAPPING:
         return jsonify({'error': 'Device not found'}), 404
         
    # If changing IP, ensure new IP doesn't conflict (unless it's the same IP)
    if old_ip != new_ip and new_ip in UPS_NAME_MAPPING:
        return jsonify({'error': 'New IP Address already exists'}), 400

    # Remove old entry
    del UPS_NAME_MAPPING[old_ip]
    if old_ip in ups_data_cache:
        del ups_data_cache[old_ip]
        
    # Add new entry
    UPS_NAME_MAPPING[new_ip] = new_name
    save_inventory()
    
    # Trigger immediate poll
    threading.Thread(target=lambda: ups_data_cache.update({new_ip: get_snmp_data(new_ip, new_name)})).start()
    
    return jsonify({'success': True})


@app.route('/api/ups-logs', methods=['GET'])
@login_required
def get_ups_logs():
    target_ip = request.args.get('ip')
    if not target_ip:
        return jsonify({'error': 'No IP provided'}), 400
    
    # Use current dynamic mapping for security check
    if target_ip not in UPS_NAME_MAPPING:
        return jsonify({'error': 'Unknown Device'}), 403

    protocol = detect_protocol(target_ip)
    base_url = f'{protocol}://{target_ip}'
    
    try:
        session = requests.Session()
        requests.packages.urllib3.disable_warnings() 
        login_payload = {'login_username': UPS_WEB_USER, 'login_password': UPS_WEB_PASS, 'submit': 'Log On'}
        try:
            session.post(f'{base_url}/forms/login', data=login_payload, verify=False, timeout=5)
        except: pass 
        
        log_url = f'{base_url}/datalogs.htm'
        response = session.get(log_url, verify=False, timeout=5)
        
        if response.status_code == 404:
            log_url = f'{base_url}/logs/datalogs.htm'
            response = session.get(log_url, verify=False, timeout=5)

        if response.status_code != 200: return jsonify([]), 502

        soup = BeautifulSoup(response.text, 'html.parser')
        data_rows = []
        table = None
        for t in soup.find_all('table'):
            if 'Date' in t.text and 'Time' in t.text and 'Vmin' in t.text:
                table = t
                break
        
        if not table: return jsonify([]), 500

        rows = table.find_all('tr')[1:] 
        for row in rows:
            cols = row.find_all('td')
            if len(cols) >= 8:
                try:
                    entry = {
                        'time': cols[1].text.strip(),
                        'vmin': float(cols[2].text.strip()),
                        'vout': float(cols[4].text.strip()),
                        'load': float(cols[6].text.strip()), 
                        'capacity': float(cols[9].text.strip())
                    }
                    data_rows.append(entry)
                except ValueError: continue 
        return jsonify(data_rows[::-1])

    except Exception as e:
        print(f'Scraping Error {target_ip}: {e}')
        return jsonify({'error': str(e)}), 500

@app.route('/api/server-stats', methods=['GET'])
@login_required
def get_server_stats():
    cpu_pct = psutil.cpu_percent(interval=None)
    load1, load5, load15 = psutil.getloadavg()
    ram = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disk = psutil.disk_usage('/')
    boot_time = datetime.fromtimestamp(psutil.boot_time())
    uptime_delta = datetime.now() - boot_time
    days = uptime_delta.days
    hours, remainder = divmod(uptime_delta.seconds, 3600)
    minutes, _ = divmod(remainder, 60)
    uptime_str = f'{days}d {hours}h {minutes}m'
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
        s.close()
    except: ip = '127.0.0.1'
    return jsonify({
        'cpu': cpu_pct, 'load_1': round(load1, 2), 'load_5': round(load5, 2),
        'ram_percent': ram.percent, 'swap_percent': swap.percent, 'disk_percent': disk.percent,
        'uptime': uptime_str, 'ip': ip
    })

@app.route('/api/cisa-feed', methods=['GET'])
@login_required
def get_cisa_feed():
    feed_url = 'https://www.cisa.gov/cybersecurity-advisories/all.xml'
    items = []
    try:
        req = urllib.request.Request(feed_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            root = ET.fromstring(response.read())
            for item in root.findall('./channel/item')[:6]: 
                items.append({'title': item.find('title').text, 'link': item.find('link').text, 'pubDate': item.find('pubDate').text})
    except Exception as e:
        print(f'CISA Feed Error: {e}')
        return jsonify([]), 200 
    return jsonify(items)

@app.route('/api/domain-audit', methods=['GET'])
@login_required
def get_domain_audit():
    return jsonify(domain_audit_cache)

@app.route('/api/nmap-scan', methods=['GET'])
@login_required
def run_nmap_scan():
    target = request.args.get('target')
    scan_type = request.args.get('type', 'quick')
    if not target: return jsonify({'error': 'No target specified'}), 400
    nm = nmap.PortScanner()
    try:
        if scan_type == 'quick': args = '-T4 -F' 
        elif scan_type == 'intense': args = '-T4 -A -v'
        elif scan_type == 'vuln': args = '-T4 --script=vuln'
        else: args = '-T4 -F'
        nm.scan(target, arguments=args)
        if target in nm.all_hosts():
            host_data = nm[target]
            open_ports = []
            for proto in host_data.all_protocols():
                ports = host_data[proto].keys()
                for port in sorted(ports):
                    if host_data[proto][port]['state'] == 'open':
                        svc = host_data[proto][port]
                        open_ports.append({'port': port, 'protocol': proto, 'service': svc['name'], 'detail': f'{svc.get("product","")}'.strip()})
            return jsonify({'status': 'up', 'hostname': host_data.hostname(), 'ports': open_ports, 'command': nm.command_line()})
        else: return jsonify({'status': 'down', 'message': 'Host unreachable'})
    except Exception as e: return jsonify({'error': str(e)}), 500

# --- Application Startup ---
if not shutil.which('snmpget'):
    print('WARNING: snmpget command not found. UPS polling threads will likely fail.')

threading.Thread(target=poll_ups_devices, daemon=True).start()
threading.Thread(target=poll_domains, daemon=True).start()