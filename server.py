import os
import subprocess
import json
import re
import socket
import time
import psutil
import urllib.request
from datetime import datetime
from functools import wraps, lru_cache
from flask import Flask, render_template, request, jsonify, session, redirect, url_for

app = Flask(__name__)

# Читаем данные из системных переменных. Если их нет - используем дефолтные.
app.secret_key = os.getenv('PANEL_SECRET_KEY', 'fallback_secret_key_123') 
ADMIN_USERNAME = os.getenv('PANEL_ADMIN_USER', 'admin')
ADMIN_PASSWORD = os.getenv('PANEL_ADMIN_PASS', 'password')

# === НАСТРОЙКИ ПАНЕЛИ ===
SERVICE_PREFIX = "flaskbot_"
SYSTEMD_DIR = "/etc/systemd/system"
DEFAULT_DIR = "/root/Bots"
BOTS_ORDER_FILE = "bots_order.json"
LIMITS_FILE = "ip_limits.json"
CUSTOM_NAMES_FILE = "custom_names.json"

APP_START_TIME = time.time()

# Глобальные переменные для кэша и мониторинга
last_net_io = None
last_net_time = 0
proc_cache = {}
_proxy_pids_cache = set()
_proxy_pids_time = 0
_outline_cache = ({}, {})
_outline_time = 0

# Регулярное выражение для удаления ANSI цветовых кодов из логов
ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

def clean_logs(logs_str):
    return ansi_escape.sub('', logs_str)

# === ДЕКОРАТОР АВТОРИЗАЦИИ ===
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            if request.path.startswith('/api/'):
                return jsonify({"success": False, "error": "Необходима авторизация"}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def run_command(cmd):
    try:
        result = subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        return e.stderr.strip()


# ========================================
# УПРАВЛЕНИЕ ИМЕНАМИ И СКОРОСТЬЮ (Traffic Control)
# ========================================
def get_custom_names():
    if os.path.exists(CUSTOM_NAMES_FILE):
        try:
            with open(CUSTOM_NAMES_FILE, 'r') as f:
                return json.load(f)
        except: pass
    return {}

def save_custom_names(names):
    with open(CUSTOM_NAMES_FILE, 'w') as f:
        json.dump(names, f)

def get_limits():
    if os.path.exists(LIMITS_FILE):
        try:
            with open(LIMITS_FILE, 'r') as f:
                return json.load(f)
        except: pass
    return {}

def save_limits(limits):
    with open(LIMITS_FILE, 'w') as f:
        json.dump(limits, f)

def get_main_interface():
    try:
        out = run_command("ip route get 8.8.8.8")
        match = re.search(r'dev\s+([^\s]+)', out)
        return match.group(1) if match else "eth0"
    except:
        return "eth0"

def sync_tc_rules():
    """Синхронизирует правила Linux TC с нашим файлом"""
    iface = get_main_interface()
    limits = get_limits()
    run_command(f"tc qdisc del dev {iface} root")
    if not limits: return
    run_command(f"tc qdisc add dev {iface} root handle 1: htb default 10")
    run_command(f"tc class add dev {iface} parent 1: classid 1:10 htb rate 1000mbit")
    for ip, data in limits.items():
        cid = data['class_id']
        speed = data['speed']
        run_command(f"tc class add dev {iface} parent 1: classid 1:{cid} htb rate {speed}mbit")
        run_command(f"tc filter add dev {iface} protocol ip parent 1:0 prio 1 u32 match ip dst {ip}/32 flowid 1:{cid}")

sync_tc_rules()


# ========================================
# ФУНКЦИИ ДЛЯ БОТОВ И СЕРВИСОВ
# ========================================
def get_saved_order():
    if os.path.exists(BOTS_ORDER_FILE):
        try:
            with open(BOTS_ORDER_FILE, 'r') as f:
                return json.load(f)
        except: pass
    return []

def save_bots_order(order_list):
    with open(BOTS_ORDER_FILE, 'w') as f:
        json.dump(order_list, f)

def get_exec_path(service_name, extract_python=False):
    try:
        res = subprocess.run(['systemctl', 'show', '-p', 'ExecStart', service_name], capture_output=True, text=True)
        path = ""
        match = re.search(r'argv\[\]=(.*?)\s+;', res.stdout)
        if match:
            path = match.group(1).strip()
        else:
            match_path = re.search(r'path=(.*?)\s+;', res.stdout)
            if match_path:
                path = match_path.group(1).strip()
                
        if path:
            is_python = False
            python_path = ""
            if extract_python:
                parts = path.split()
                if parts and 'python' in parts[0].lower():
                    is_python = True
                    python_path = parts[0]
                    if len(parts) > 1:
                        path = " ".join(parts[1:])
            return path, is_python, python_path
    except: pass
    return "Путь неизвестен", False, ""

def get_bots():
    bots = []
    if not os.path.exists(SYSTEMD_DIR): return bots
    for file in os.listdir(SYSTEMD_DIR):
        if file.startswith(SERVICE_PREFIX) and file.endswith(".service"):
            bot_name = file[len(SERVICE_PREFIX):-8]
            service_name = file
            status = run_command(f"systemctl is-active {service_name}")
            logs = run_command(f"journalctl -u {service_name} -n 15 --no-pager --output=cat")
            exec_path, is_python, python_path = get_exec_path(service_name, extract_python=True) 
            bots.append({
                "name": bot_name, "service": service_name, "active": (status == "active"), 
                "path": exec_path, "is_python": is_python, "python_path": python_path, "logs": clean_logs(logs)
            })
            
    saved_order = get_saved_order()
    def sort_key(bot):
        try: return saved_order.index(bot['name'])
        except ValueError: return 999999 
    bots.sort(key=sort_key)
    return bots

def get_all_services():
    try:
        # Сверхбыстрый сбор системных сервисов
        res = subprocess.run(['systemctl', 'list-units', '--type=service', '--all', '--no-pager', '--no-legend'], capture_output=True, text=True)
        service_names = [line.split()[0] for line in res.stdout.split('\n') if line.strip() and line.split()[0].endswith('.service')]
        if not service_names: return []

        cmd = ['systemctl', 'show', '-p', 'Id,ActiveState,ExecStart'] + service_names
        res2 = subprocess.run(cmd, capture_output=True, text=True)
        services = []
        current_svc = {}
        lines = res2.stdout.split('\n')
        lines.append('')
        
        for line in lines:
            line = line.strip()
            if not line:
                if 'Id' in current_svc and current_svc['Id'].endswith('.service'):
                    path_raw = current_svc.get('ExecStart', '')
                    clean_path = ""
                    match_argv = re.search(r'argv\[\]=(.*?)\s+;', path_raw)
                    if match_argv: clean_path = match_argv.group(1).strip()
                    else:
                        match_path = re.search(r'path=(.*?)\s+;', path_raw)
                        if match_path: clean_path = match_path.group(1).strip()
                    services.append({
                        "name": current_svc['Id'], "service": current_svc['Id'],
                        "active": (current_svc.get('ActiveState') == 'active'), "path": clean_path,
                        "logs": "Нажмите кнопку обновления логов (📄) для загрузки."
                    })
                current_svc = {}
            elif '=' in line:
                key, val = line.split('=', 1)
                current_svc[key] = val
        return services
    except Exception as e:
        print(f"Ошибка получения сервисов: {e}")
        return []


# ========================================
# ФУНКЦИИ ДЛЯ VPN / XRAY / OUTLINE / ПРОКСИ
# ========================================
def get_outline_status():
    try:
        res = subprocess.run(['docker', 'ps', '--filter', 'name=shadowbox', '--format', '{{.Status}}'], capture_output=True, text=True)
        return "active" if "Up" in res.stdout else "inactive"
    except: return "unknown"

def get_outline_metrics():
    data = []
    keys_info = {}
    config_path = '/opt/outline/persisted-state/shadowbox_config.json'
    try:
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = json.load(f)
                keys_list = config.get('accessKeys', config.get('keys', []))
                for k in keys_list:
                    kid = str(k.get('id'))
                    name = k.get('name')
                    keys_info[kid] = name if name else f"Без имени (ID: {kid})"
    except: pass

    container_name = "shadowbox"
    try:
        res = subprocess.run(['docker', 'ps', '--format', '{{.Names}}'], capture_output=True, text=True)
        if 'shadowbox' not in res.stdout:
            res2 = subprocess.run(['docker', 'ps', '--filter', 'ancestor=quay.io/outline/shadowbox', '--format', '{{.Names}}'], capture_output=True, text=True)
            if res2.stdout.strip(): container_name = res2.stdout.strip().split('\n')[0]
    except: pass

    metrics_dict = {}
    try:
        res = subprocess.run(['docker', 'exec', container_name, 'wget', '-qO-', 'http://localhost:9092/metrics'], capture_output=True, text=True)
        if not res.stdout.strip():
             res = subprocess.run(['docker', 'exec', container_name, 'curl', '-s', 'http://localhost:9092/metrics'], capture_output=True, text=True)
        for line in res.stdout.split('\n'):
            if line.startswith('shadowsocks_data_bytes'):
                match = re.search(r'access_key="([^"]+)"', line)
                if match:
                    kid = match.group(1)
                    try: metrics_dict[kid] = metrics_dict.get(kid, 0) + float(line.split()[-1])
                    except: pass
    except: pass

    for kid, bytes_total in metrics_dict.items():
        name = keys_info.get(kid, f"Неизвестный ключ (ID: {kid})")
        if bytes_total > 1024**3: usage = f"{(bytes_total / 1024**3):.2f} GB"
        else: usage = f"{(bytes_total / 1024**2):.2f} MB"
        data.append({'id': kid, 'name': name, 'usage': usage, 'raw_bytes': bytes_total})
    data.sort(key=lambda x: x['raw_bytes'], reverse=True)
    return data

def get_mtproto_status():
    try:
        res = subprocess.run(['docker', 'ps', '--filter', 'name=mtproto-proxy', '--format', '{{.Status}}'], capture_output=True, text=True)
        return "active" if "Up" in res.stdout else "inactive"
    except: return "unknown"

def get_mtproto_stats():
    stats = {"uptime": "0", "active_connections": "0", "total_connections": "0", "version": "Неизвестно"}
    try:
        res = subprocess.run(['docker', 'exec', 'mtproto-proxy', 'curl', '-s', 'http://localhost:2398/stats'], capture_output=True, text=True)
        for line in res.stdout.split('\n'):
            parts = line.split('\t')
            if len(parts) >= 2:
                if parts[0] == 'uptime': stats['uptime'] = parts[1]
                elif parts[0] == 'active_connections': stats['active_connections'] = parts[1]
                elif parts[0] == 'total_connections': stats['total_connections'] = parts[1]
                elif parts[0] == 'version': stats['version'] = parts[1]
    except: pass
    
    try:
        secs = int(stats['uptime'])
        m, s = divmod(secs, 60)
        h, m = divmod(m, 60)
        d, h = divmod(h, 24)
        stats['uptime_formatted'] = f"{d}д {h}ч {m}м"
    except:
        stats['uptime_formatted'] = "0д 0ч 0м"
    return stats

def get_proxy_pids():
    """Кэширует список PID процессов на 15 секунд"""
    global _proxy_pids_cache, _proxy_pids_time
    if time.time() - _proxy_pids_time > 15:
        pids = set()
        proxy_names = ['xray', '3proxy', 'danted', 'shadowbox', 'docker-proxy', 'mtproto-proxy']
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                name = proc.info['name'].lower()
                if any(p in name for p in proxy_names):
                    pids.add(proc.info['pid'])
            except: pass
        _proxy_pids_cache = pids
        _proxy_pids_time = time.time()
    return _proxy_pids_cache

def get_outline_connections():
    """Кэширует запрос к Docker на 3 секунды"""
    global _outline_cache, _outline_time
    if time.time() - _outline_time < 3:
        return _outline_cache

    inbound, outbound = {}, {}
    container_name = "shadowbox"
    try:
        res = subprocess.run(['docker', 'ps', '--format', '{{.Names}}'], capture_output=True, text=True)
        if 'shadowbox' not in res.stdout:
            res2 = subprocess.run(['docker', 'ps', '--filter', 'ancestor=quay.io/outline/shadowbox', '--format', '{{.Names}}'], capture_output=True, text=True)
            if res2.stdout.strip(): container_name = res2.stdout.strip().split('\n')[0]
            
        net_res = subprocess.run(['docker', 'exec', container_name, 'netstat', '-tun'], capture_output=True, text=True)
        for line in net_res.stdout.split('\n'):
            line = line.strip()
            if 'ESTABLISHED' in line or line.startswith('udp'):
                parts = line.split()
                if len(parts) >= 5:
                    local_addr, foreign_addr = parts[3], parts[4]
                    if ':' not in local_addr or ':' not in foreign_addr: continue
                    f_ip, f_port = foreign_addr.rsplit(':', 1)
                    l_ip, l_port = local_addr.rsplit(':', 1)
                    f_ip = f_ip.replace('::ffff:', '')
                    if f_ip in ('127.0.0.1', '::1', '0.0.0.0', '*'): continue
                    try:
                        f_port_num, l_port_num = int(f_port), int(l_port)
                        if f_port_num < 10240 and l_port_num > 10240: outbound[f_ip] = outbound.get(f_ip, 0) + 1
                        else: inbound[f_ip] = inbound.get(f_ip, 0) + 1
                    except: pass
    except: pass
    
    _outline_cache = (inbound, outbound)
    _outline_time = time.time()
    return _outline_cache

def get_active_vpn_users():
    proxy_pids = get_proxy_pids() 
    inbound_ips, outbound_ips = {}, {}
    
    local_ips = set()
    for interface, snics in psutil.net_if_addrs().items():
        for snic in snics:
            if snic.family == socket.AF_INET: local_ips.add(snic.address)

    listening_ports = set()
    for conn in psutil.net_connections(kind='inet'):
        if conn.pid in proxy_pids:
            if conn.status == 'LISTEN' or conn.type == socket.SOCK_DGRAM:
                listening_ports.add(conn.laddr.port)

    for conn in psutil.net_connections(kind='inet'):
        if conn.pid in proxy_pids and conn.raddr:
            remote_ip = conn.raddr.ip
            local_ip = conn.laddr.ip
            if remote_ip in local_ips or remote_ip.startswith('127.') or remote_ip.startswith('::1'): continue
            if remote_ip.startswith('172.') and local_ip.startswith('172.'): continue
            
            if conn.laddr.port in listening_ports:
                inbound_ips[remote_ip] = inbound_ips.get(remote_ip, 0) + 1
            else:
                outbound_ips[remote_ip] = outbound_ips.get(remote_ip, 0) + 1

    out_inbound, out_outbound = get_outline_connections()
    for ip, count in out_inbound.items(): inbound_ips[ip] = inbound_ips.get(ip, 0) + count
    for ip, count in out_outbound.items(): outbound_ips[ip] = outbound_ips.get(ip, 0) + count

    return inbound_ips, outbound_ips

@lru_cache(maxsize=2000)
def reverse_dns(ip):
    try:
        if ip.startswith(('192.168.', '10.', '172.', '127.')): return None
        socket.setdefaulttimeout(0.05) 
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname if hostname != ip else None
    except: return None

def get_recent_connections(skip_dns=False):
    """Парсер логов Xray с сортировкой: СНАЧАЛА НОВЫЕ"""
    try:
        result = subprocess.run(['tail', '-100', '/var/log/xray/access.log'], capture_output=True, text=True)
        connections = []
        seen = set()
        for line in reversed(result.stdout.split('\n')):
            if not line.strip(): continue
            match = re.search(r'(\d{2}:\d{2}:\d{2}).*?(?:from\s+)?([a-fA-F0-9\.:]+):\d+\s+accepted\s+[a-zA-Z0-9]+:([a-zA-Z0-9\.\-]+):(\d+)\s+\[([^\]]+)\]', line)
            if match:
                time_str, client_ip, dest_ip, port, route = match.groups()
                
                user = "-"
                email_match = re.search(r'email:\s*([^\s]+)', line)
                if email_match: user = email_match.group(1)
                
                key = f"{client_ip}:{dest_ip}:{port}:{route}"
                if key in seen: continue
                seen.add(key)
                
                if skip_dns or dest_ip.replace('.', '').isdigit() == False:
                    domain = dest_ip
                else:
                    domain = reverse_dns(dest_ip)
                    
                connections.append({
                    'time': time_str, 'client': client_ip, 'user': user, 'dest': f"{dest_ip}:{port}",
                    'domain': domain, 'route': route, 'route_class': 'direct' if route == 'direct' else 'vless'
                })
        return connections[:30]
    except: return []

def get_3proxy_connections():
    possible_paths = ['/var/log/3proxy.log', '/var/log/3proxy/3proxy.log', '/var/log/3proxy']
    log_file = next((path for path in possible_paths if os.path.isfile(path)), None)
    if not log_file: return [{"time": "-", "user": "-", "client": "-", "dest": "ОШИБКА", "status": "Файл лога 3proxy не найден"}]

    try:
        res = subprocess.run(['tail', '-100', log_file], capture_output=True, text=True)
        connections = []
        for line in reversed(res.stdout.split('\n')):
            if not line.strip(): continue
            parts = line.split()
            if len(parts) >= 10:
                try: time_str = datetime.fromtimestamp(float(parts[0])).strftime('%d.%m %H:%M:%S')
                except: time_str = parts[0]
                user, event = parts[3], parts[9]
                if 'Accepting_connections' in event: continue
                if event.startswith('CONNECT_'): event = 'CONNECT'
                elif event.startswith('UNKNOWN_'): event = 'UNKNOWN'
                connections.append({
                    'time': time_str, 'user': user if user != '-' else 'Unknown',
                    'client': parts[4], 'dest': parts[5], 'status': event
                })
        return connections[:50]
    except Exception as e: return [{"time": "-", "user": "-", "client": "-", "dest": "ОШИБКА", "status": str(e)}]

def get_danted_connections():
    try:
        res = subprocess.run(['tail', '-100', '/var/log/socks.log'], capture_output=True, text=True)
        connections = []
        for line in reversed(res.stdout.split('\n')):
            if not line.strip(): continue
            time_match = re.search(r'^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})', line)
            time_str = time_match.group(1) if time_match else ""
            status = "pass" if "pass(" in line else "block" if "block(" in line else "info"
            client, dest, user = "unknown", "unknown", "-"
            
            user_m = re.search(r'username%([^@\s]+)@', line)
            if user_m: user = user_m.group(1)
            
            if "tcp/connect" in line:
                client_m = re.search(r'@(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.\d+', line)
                if client_m: client = client_m.group(1)
                dest_m = re.search(r'->\s+[\d\.]+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d+)', line)
                if dest_m: dest = f"{dest_m.group(1)}:{dest_m.group(2)}"
            elif "tcp/accept" in line:
                m = re.search(r'[:\]]\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.\d+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if m: client, dest = m.group(1), f"Local: {m.group(2)}"

            if client != "unknown":
                raw_log = line.split(']: ')[-1] if ']: ' in line else line
                if user != "-": raw_log = re.sub(r'username%[^@]+@', '', raw_log)
                connections.append({'time': time_str, 'client': client, 'dest': dest, 'user': user, 'status': status, 'raw': raw_log})
        return connections[:50]
    except: return []

def get_dns_queries():
    try:
        result = subprocess.run(['tail', '-200', '/var/log/dnsmasq.log'], capture_output=True, text=True)
        queries, seen = [], set()
        for line in result.stdout.split('\n'):
            match = re.search(r'(\d{2}:\d{2}:\d{2}).*query\[(\w+)\] ([^\s]+) from ([\d.]+)', line)
            if match:
                time, qtype, domain, client = match.groups()
                key = f"{domain}:{client}"
                if key not in seen and not domain.startswith('in-addr.arpa'):
                    seen.add(key)
                    queries.append({'time': time, 'client': client, 'domain': domain, 'type': qtype})
        return queries[:50]
    except: return []

def analyze_proxy_logs():
    ip_to_users, target_to_users = {}, {}
    def add_user_to_ip(ip, user):
        if user and user not in ('-', 'Unknown', 'unknown'):
            if ip not in ip_to_users: ip_to_users[ip] = set()
            ip_to_users[ip].add(user)
    def add_target(target, client_ip, user):
        target_ip = target.split(':')[0]
        if target_ip not in target_to_users: target_to_users[target_ip] = set()
        if user and user not in ('-', 'Unknown', 'unknown'): target_to_users[target_ip].add(user)
        else: target_to_users[target_ip].add(client_ip)

    try:
        for c in get_3proxy_connections():
            client_ip, user = c['client'].split(':')[0], c['user']
            add_user_to_ip(client_ip, user)
            if c['dest'] != 'ОШИБКА': add_target(c['dest'], client_ip, user)
    except: pass
    try:
        for c in get_danted_connections():
            client_ip, user = c['client'].split(':')[0], c['user']
            add_user_to_ip(client_ip, user)
            if c['dest'] != 'unknown' and not str(c['dest']).startswith('Local:'): add_target(c['dest'], client_ip, user)
    except: pass
    try:
        for c in get_recent_connections(skip_dns=True):
            client_ip = c['client']
            user = c.get('user', '-')
            add_user_to_ip(client_ip, user)
            add_target(c['dest'], client_ip, user)
    except: pass
    
    final_target_to_user = {}
    for target, userset in target_to_users.items():
        final_set = set()
        for u in userset:
            if u in ip_to_users:
                for known_user in ip_to_users[u]: final_set.add(known_user)
            else: final_set.add(u)
        final_target_to_user[target] = list(final_set)
    final_ip_to_users = {ip: ", ".join(users) for ip, users in ip_to_users.items()}
    return final_ip_to_users, final_target_to_user

# ========================================
# АНАЛИТИКА САЙТА (NGINX + XRAY FALLBACKS)
# ========================================

def format_uptime(seconds):
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    d, h = divmod(h, 24)
    return f"{d}д {h}ч {m}м"

def get_site_uptime():
    try:
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.readline().split()[0])
            return format_uptime(uptime_seconds)
    except: return "Неизвестно"

def get_app_uptime():
    return format_uptime(time.time() - APP_START_TIME)

def get_nginx_unique_stats():
    """Считает уникальные IP и делит их на людей (код 200) и ботов (коды 301, 40x, 50x)"""
    humans = set()
    bots = set()
    try:
        if os.path.exists('/var/log/nginx/access.log'):
            # Читаем последние 5000 строк для надежной статистики
            res = subprocess.run(['tail', '-n', '5000', '/var/log/nginx/access.log'], capture_output=True, text=True)
            for line in res.stdout.split('\n'):
                if not line.strip(): continue
                parts = line.split('"')
                if len(parts) >= 3:
                    ip_date = parts[0].strip()
                    status_code = parts[2].strip().split()[0]
                    
                    ip_match = re.search(r'^([\d\.]+)', ip_date)
                    if ip_match:
                        ip = ip_match.group(1)
                        # Игнорируем локальные IP (чтобы панель не считала саму себя)
                        if ip == '127.0.0.1': continue
                        
                        # Коды 200 (ОК) - это люди
                        if status_code.startswith('2'):
                            humans.add(ip)
                        # Ошибки и 301 (Редирект/Сканеры) - это боты
                        elif status_code.startswith(('301', '4', '5')):
                            bots.add(ip)
    except: pass
    
    # Если IP попал и в боты, и в люди (например, человек сначала словил 404, а потом зашел нормально)
    # мы считаем его человеком
    pure_bots = bots - humans
    
    return {
        "total": len(humans) + len(pure_bots),
        "humans": len(humans),
        "bots": len(pure_bots)
    }
                           
def parse_nginx_date(date_str):
    months = {'Jan':'01', 'Feb':'02', 'Mar':'03', 'Apr':'04', 'May':'05', 'Jun':'06', 
              'Jul':'07', 'Aug':'08', 'Sep':'09', 'Oct':'10', 'Nov':'11', 'Dec':'12'}
    try:
        parts = date_str.split('/')
        day = parts[0]
        month = months[parts[1]]
        year_time = parts[2].split(':')
        year = year_time[0]
        time = ":".join(year_time[1:])
        return f"{year}/{month}/{day} {time}"
    except:
        return date_str

@app.route('/api/site_analytics', methods=['GET'])
@login_required
def api_site_analytics():
    nginx_logs = {}
    try:
        if os.path.exists('/var/log/nginx/access.log'):
            res_nginx = subprocess.run(['tail', '-n', '1000', '/var/log/nginx/access.log'], capture_output=True, text=True)
            for line in res_nginx.stdout.split('\n'):
                if not line.strip(): continue
                parts = line.split('"')
                if len(parts) >= 3:
                    ip_date = parts[0].strip()
                    request_info = parts[1]
                    status_code = parts[2].strip().split()[0]
                    ip_match = re.search(r'^([\d\.]+)', ip_date)
                    date_match = re.search(r'\[(.*?) \+', ip_date)
                    if ip_match and date_match:
                        ip = ip_match.group(1)
                        n_date = parse_nginx_date(date_match.group(1))
                        if ip not in nginx_logs: nginx_logs[ip] = []
                        nginx_logs[ip].append({"time": n_date, "request": request_info, "status": status_code})
    except: pass

    xray_sessions = {}
    try:
        res_xray = subprocess.run(['journalctl', '-u', 'xray', '-n', '2000', '--no-pager'], capture_output=True, text=True)
        for line in res_xray.stdout.split('\n'):
            if not line.strip(): continue
            match = re.search(r'(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\.\d+\s+\[.*?\]\s+\[(\d+)\]\s+(.*)', line)
            if match:
                time_str, conn_id, msg = match.groups()
                if conn_id not in xray_sessions:
                    xray_sessions[conn_id] = {"time": time_str, "ip": None, "is_fallback": False, "real_name": "", "error": None, "is_vpn": True}
                session = xray_sessions[conn_id]
                if 'fallback starts' in msg:
                    session['is_fallback'] = True
                    session['is_vpn'] = False
                elif 'realName =' in msg:
                    session['real_name'] = msg.split('=')[-1].strip()
                elif 'not look like a TLS handshake' in msg or 'invalid request version' in msg:
                    session['error'] = "Неизвестный протокол (Не TLS)"
                    session['is_vpn'] = False
                ip_match = re.search(r'->([\d\.]+):\d+', msg)
                if ip_match: session['ip'] = ip_match.group(1)
    except: pass

    final_logs = []
    processed_nginx_ips = set()

    for conn_id, s in xray_sessions.items():
        ip = s['ip'] or "Неизвестный IP"
        time_str = s['time']
        if s['is_fallback']:
            n_log = nginx_logs.get(ip)
            if n_log:
                last_req = n_log[-1]
                processed_nginx_ips.add(ip)
                status = last_req['status']
                if status.startswith('2') or (status.startswith('3') and status != '301'):
                    final_logs.append({
                        "time": time_str, "ip": ip, "source": "Xray ➔ Nginx", "color": "success",
                        "type": "Посетитель", "desc": f"Успешный вход на сайт. Запрос: {last_req['request']} (Код: {status})"
                    })
                # Если 301, 400+, 500+ - это бот/сканер
                elif status == '301' or status.startswith(('4', '5')):
                    final_logs.append({
                        "time": time_str, "ip": ip, "source": "Xray ➔ Nginx", "color": "danger",
                        "type": "Сканер / Бот", "desc": f"Попытка сканирования сайта. Запрос: {last_req['request']} (Код: {status})"
                    })
            else:
                final_logs.append({"time": time_str, "ip": ip, "source": "Xray", "color": "warning", "type": "Fallback (Сброс)", "desc": f"SNI: {s['real_name']}. Трафик перенаправлен, но до Nginx не дошел."})
        elif s['error']:
            final_logs.append({"time": time_str, "ip": ip, "source": "Xray", "color": "danger", "type": "Сканер портов", "desc": f"Попытка простучать 443 порт. Ошибка: {s['error']}"})
            
    # 4. ДОБАВЛЯЕМ ПРЯМЫЕ ЗАПРОСЫ В NGINX (на порт 80)
    for ip, reqs in nginx_logs.items():
        if ip not in processed_nginx_ips:
            for req in reqs:
                status = req['status']
                if status == '301' or status.startswith(('4', '5')):
                    final_logs.append({
                        "time": req['time'], "ip": ip, "source": "Nginx (80 порт)", "color": "danger",
                        "type": "Сканер / Бот", "desc": f"Прямой запрос по HTTP. Запрос: {req['request']} (Код: {status})"
                    })
                elif status.startswith('2') or (status.startswith('3') and status != '301'):
                    final_logs.append({
                        "time": req['time'], "ip": ip, "source": "Nginx (80 порт)", "color": "success",
                        "type": "Посетитель", "desc": f"# 4. ДОБАВЛЯЕМ ПРЯМЫЕ ЗАПРОСЫ В NGINX (на порт 80)
    for ip, reqs in nginx_logs.items():
        if ip not in processed_nginx_ips:
            for req in reqs:
                status = req['status']
                if status == '301' or status.startswith(('4', '5')):
                    final_logs.append({
                        "time": req['time'], "ip": ip, "source": "Nginx (80 порт)", "color": "danger",
                        "type": "Сканер / Бот", "desc": f"Прямой запрос по HTTP. Запрос: {req['request']} (Код: {status})"
                    })
                elif status.startswith('2') or (status.startswith('3') and status != '301'):
                    final_logs.append({
                        "time": req['time'], "ip": ip, "source": "Nginx (80 порт)", "color": "success",
                        "type": "Посетитель", "desc": f"Прямой заход по HTTP. Запрос: {req['request']} (Код: {status})"
                    }) заход по HTTP. Запрос: {req['request']} (Код: {status})"
                    })

    final_logs.sort(key=lambda x: x['time'], reverse=True)
    return jsonify({"success": True, "logs": final_logs[:100]})


# ========================================
# МАРШРУТЫ (Сайт)
# ========================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form.get('username') == ADMIN_USERNAME and request.form.get('password') == ADMIN_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('index'))
        error = "Неверный логин или пароль"
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    stats = get_nginx_unique_stats()
    return render_template('site_stats.html', 
                           server_uptime=get_site_uptime(),
                           app_uptime=get_app_uptime(),
                           total_ips=stats["total"],
                           humans=stats["humans"],
                           bots=stats["bots"])

@app.route('/site_stats')
@login_required
def site_stats_page():
    return redirect(url_for('index'))

@app.route('/bots')
@login_required
def bots():
    return render_template('bots.html', bots=get_bots())

@app.route('/services')
@login_required
def system_services():
    return render_template('services.html', services=get_all_services())

@app.route('/monitor')
@login_required
def system_monitor():
    return render_template('monitor.html')

@app.route('/logs')
@login_required
def system_logs_page():
    return render_template('logs.html')

@app.route('/vpn')
@login_required
def vpn():
    return render_template('vpn.html',
                           xray_status=run_command("systemctl is-active xray") == "active",
                           proxy_status=run_command("systemctl is-active 3proxy") == "active",
                           danted_status=run_command("systemctl is-active danted") == "active",
                           outline_status=(get_outline_status() == "active"),
                           mtproto_status=(get_mtproto_status() == "active"),
                           xray_connections=get_recent_connections(),
                           proxy_connections=get_3proxy_connections(),
                           danted_connections=get_danted_connections(),
                           outline_metrics=get_outline_metrics(),
                           mtproto_stats=get_mtproto_stats(),
                           dns_queries=get_dns_queries())

@app.route('/vpn_users')
@login_required
def vpn_users_page():
    return render_template('vpn_users.html')


# ========================================
# МАРШРУТЫ (API)
# ========================================
@app.route('/api/files', methods=['POST'])
@login_required
def get_files():
    current_path = request.json.get('path', DEFAULT_DIR)
    if not os.path.isdir(current_path): current_path = '/'
    items = []
    try:
        if current_path != '/': items.append({"name": "..", "path": os.path.dirname(current_path), "type": "dir"})
        for f in sorted(os.listdir(current_path)):
            p = os.path.join(current_path, f)
            if os.path.isdir(p): items.append({"name": f, "path": p, "type": "dir"})
            elif f.endswith('.py'): items.append({"name": f, "path": p, "type": "file"})
    except Exception as e: return jsonify({"error": str(e)})
    return jsonify({"path": current_path, "items": items})

@app.route('/api/add_bot', methods=['POST'])
@login_required
def add_bot():
    file_path = request.json.get('file_path')
    bot_name = request.json.get('bot_name')
    if not file_path or not bot_name: return jsonify({"success": False, "error": "Заполните поля"})
    svc_name = f"{SERVICE_PREFIX}{bot_name}.service"
    with open(os.path.join(SYSTEMD_DIR, svc_name), 'w') as f:
        f.write(f"[Unit]\nDescription=Bot {bot_name}\nAfter=network.target\n[Service]\nExecStart=/usr/bin/python3 {file_path}\nWorkingDirectory={os.path.dirname(file_path)}\nRestart=always\nUser=root\nKillSignal=SIGINT\nTimeoutStopSec=5\n[Install]\nWantedBy=multi-user.target\n")
    run_command(f"systemctl daemon-reload && systemctl enable {svc_name} && systemctl start {svc_name}")
    return jsonify({"success": True})

@app.route('/api/save_order', methods=['POST'])
@login_required
def update_order():
    save_bots_order(request.json.get('order', []))
    return jsonify({"success": True})

@app.route('/api/action', methods=['POST'])
@login_required
def bot_action():
    bot_name, action = request.json.get('bot_name'), request.json.get('action')
    is_system = request.json.get('is_system', False)
    svc = bot_name if is_system else f"{SERVICE_PREFIX}{bot_name}.service"
    
    if action == "status_only":
        return jsonify({"success": True, "active": (run_command(f"systemctl is-active {svc}") == "active")})
        
    if action == "restart": run_command(f"systemctl restart {svc}")
    elif action == "start": run_command(f"systemctl start {svc}")
    elif action == "stop": run_command(f"systemctl stop {svc}")
    elif action == "delete":
        if is_system: return jsonify({"success": False, "error": "Удаление системных служб запрещено."})
        run_command(f"systemctl stop {svc} && systemctl disable {svc}")
        os.remove(os.path.join(SYSTEMD_DIR, svc))
        run_command("systemctl daemon-reload")
        return jsonify({"success": True})
        
    is_active = (run_command(f"systemctl is-active {svc}") == "active")
    n = 100 if action == "full_logs" else 15
    logs = run_command(f"journalctl -u {svc} -n {n} --no-pager --output=cat")
    return jsonify({"success": True, "active": is_active, "logs": clean_logs(logs)})

@app.route('/api/system_stats', methods=['GET'])
@login_required
def api_system_stats():
    global last_net_io, last_net_time, proc_cache
    cpu_percent = psutil.cpu_percent(interval=0.1)
    cpu_cores = psutil.cpu_count(logical=True)
    try: load1, load5, load15 = os.getloadavg()
    except: load1 = load5 = load15 = 0
    mem, swap, disk = psutil.virtual_memory(), psutil.swap_memory(), psutil.disk_usage('/')
    net_io, current_time = psutil.net_io_counters(), time.time()
    upload_speed, download_speed = 0, 0
    if last_net_io and last_net_time > 0:
        time_diff = current_time - last_net_time
        if time_diff > 0:
            upload_speed = ((net_io.bytes_sent - last_net_io.bytes_sent) * 8) / time_diff
            download_speed = ((net_io.bytes_recv - last_net_io.bytes_recv) * 8) / time_diff
    last_net_io, last_net_time = net_io, current_time
    
    stats = {
        "cpu": {"percent": cpu_percent, "cores": cpu_cores, "load_avg": f"{round(load1, 2)} / {round(load5, 2)} / {round(load15, 2)}"},
        "ram": {"percent": mem.percent, "used": mem.used, "total": mem.total},
        "swap": {"percent": swap.percent, "used": swap.used, "total": swap.total},
        "disk": {"percent": disk.percent, "used": disk.used, "total": disk.total},
        "network": {"upload": upload_speed, "download": download_speed}
    }
    processes = []
    current_pids = set()
    for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'memory_percent', 'memory_info']):
        try:
            pid = proc.info['pid']
            current_pids.add(pid)
            if pid not in proc_cache:
                proc_cache[pid] = proc
                proc.cpu_percent()
                cpu_usage = 0.0
            else:
                cpu_usage = proc_cache[pid].cpu_percent()
                if cpu_cores > 0: cpu_usage = cpu_usage / cpu_cores

            cmd = proc.info.get('cmdline')
            path = " ".join(cmd) if cmd else proc.info.get('name', '')
            ram_mb = proc.info['memory_info'].rss / (1024 * 1024) if proc.info.get('memory_info') else 0
            processes.append({
                "pid": pid, "name": proc.info['name'], "path": path, 
                "cpu": round(cpu_usage, 1), "ram_percent": round(proc.info['memory_percent'] or 0.0, 1), "ram_mb": round(ram_mb, 1)
            })
        except: pass
    proc_cache = {pid: proc for pid, proc in proc_cache.items() if pid in current_pids}
    processes.sort(key=lambda x: x['cpu'], reverse=True)
    return jsonify({"success": True, "stats": stats, "processes": processes[:150]})

@app.route('/api/system_logs', methods=['POST'])
@login_required
def api_system_logs():
    filters = request.json or {}
    lines = filters.get('lines', 300) 
    priority = filters.get('priority', 'all')
    search = filters.get('search', '').lower()
    cmd = f"journalctl -r -n {lines} -o json"
    if priority == 'error': cmd += " -p 0..3"
    elif priority == 'warning': cmd += " -p 4"
    elif priority == 'info': cmd += " -p 5..7"

    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        logs = []
        for line in result.stdout.split('\n'):
            if not line.strip(): continue
            try:
                entry = json.loads(line)
                msg = entry.get('MESSAGE', '')
                if isinstance(msg, list): msg = bytes(msg).decode('utf-8', errors='replace')
                elif not isinstance(msg, str): msg = str(msg)
                msg = clean_logs(msg)
                
                source = entry.get('SYSLOG_IDENTIFIER', entry.get('_SYSTEMD_UNIT', 'unknown'))
                if search and search not in msg.lower() and search not in source.lower(): continue
                
                timestamp = int(entry.get('__REALTIME_TIMESTAMP', 0)) // 1000000
                date_str = datetime.fromtimestamp(timestamp).strftime('%d.%m %H:%M:%S') if timestamp else ""
                
                prio_num = int(entry.get('PRIORITY', 6))
                if prio_num <= 3: prio_str = "ERROR"
                elif prio_num == 4: prio_str = "WARNING"
                else: prio_str = "INFO"

                logs.append({"time": date_str, "priority": prio_str, "source": source, "message": msg})
            except: pass
        return jsonify({"success": True, "logs": logs})
    except Exception as e: return jsonify({"success": False, "error": str(e)})

@app.route('/api/outline/reset', methods=['POST'])
@login_required
def reset_outline_stats():
    container_name = "shadowbox"
    try:
        res = subprocess.run(['docker', 'ps', '--format', '{{.Names}}'], capture_output=True, text=True)
        if 'shadowbox' not in res.stdout:
            res2 = subprocess.run(['docker', 'ps', '--filter', 'ancestor=quay.io/outline/shadowbox', '--format', '{{.Names}}'], capture_output=True, text=True)
            if res2.stdout.strip(): container_name = res2.stdout.strip().split('\n')[0]
        subprocess.run(['docker', 'restart', container_name])
        return jsonify({"success": True})
    except Exception as e: return jsonify({"success": False, "error": str(e)})

@app.route('/api/vpn/action', methods=['POST'])
@login_required
def api_vpn_action():
    service = request.json.get('service')
    action = request.json.get('action') 
    try:
        if service in ['xray', '3proxy', 'danted']:
            run_command(f"systemctl {action} {service}")
        elif service in ['outline', 'mtproto']:
            container = "shadowbox" if service == "outline" else "mtproto-proxy"
            if service == "outline":
                res = subprocess.run(['docker', 'ps', '-a', '--filter', 'ancestor=quay.io/outline/shadowbox', '--format', '{{.Names}}'], capture_output=True, text=True)
                if res.stdout.strip(): container = res.stdout.strip().split('\n')[0]
            run_command(f"docker {action} {container}")
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/ip_info/<ip>', methods=['GET'])
@login_required
def api_ip_info(ip):
    try:
        url = f"https://ipinfo.io/{ip}/json"
        req = urllib.request.Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'Accept': 'application/json'
        })
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode())
            if data.get('bogon'):
                return jsonify({"success": False, "error": "Локальный IP адрес"})
            return jsonify({"success": True, "data": data})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/vpn_users', methods=['GET'])
@login_required
def api_vpn_users():
    inbound, outbound = get_active_vpn_users()
    limits = get_limits()
    known_users, target_to_user = analyze_proxy_logs()
    custom_names = get_custom_names() 
    
    inbound_list = []
    for ip in set(inbound.keys()).union(set(limits.keys())):
        username = custom_names.get(ip, known_users.get(ip, ""))
        inbound_list.append({
            "ip": ip, "username": username,
            "connections": inbound.get(ip, 0), "limit": limits.get(ip, {}).get('speed', None)
        })
    inbound_list.sort(key=lambda x: (x['connections'] > 0, x['connections']), reverse=True)

    outbound_list = []
    for ip, count in outbound.items():
        domain = reverse_dns(ip)
        users_list = target_to_user.get(ip, [])
        if not users_list and domain and domain in target_to_user: users_list = target_to_user[domain]
        
        final_users = []
        for u in users_list:
            final_users.append(custom_names.get(u, u))
            
        outbound_list.append({"ip": ip, "domain": domain if domain else "", "connections": count, "users": ", ".join(final_users) if final_users else "Неизвестно"})
    outbound_list.sort(key=lambda x: x['connections'], reverse=True)

    return jsonify({"success": True, "inbound": inbound_list, "outbound": outbound_list})

@app.route('/api/set_custom_name', methods=['POST'])
@login_required
def api_set_custom_name():
    ip = request.json.get('ip')
    name = request.json.get('name')
    names = get_custom_names()
    if not name or name.strip() == "":
        if ip in names: del names[ip]
    else:
        names[ip] = name.strip()
    save_custom_names(names)
    return jsonify({"success": True})

@app.route('/api/set_speed_limit', methods=['POST'])
@login_required
def api_set_speed_limit():
    ip, speed = request.json.get('ip'), request.json.get('speed')
    limits = get_limits()
    if speed is None or speed == 0:
        if ip in limits: del limits[ip]
    else:
        existing_ids = [v['class_id'] for v in limits.values()]
        new_id = 11
        while new_id in existing_ids: new_id += 1
        limits[ip] = {"class_id": new_id, "speed": int(speed)}
        
    save_limits(limits)
    sync_tc_rules() 
    return jsonify({"success": True})

if __name__ == '__main__':
    # Если вы используете Nginx + Gunicorn, эта строчка игнорируется.
    # Она нужна только если вы запускаете скрипт вручную для тестов: python3 server.py
    app.run(host='0.0.0.0', port=5000)