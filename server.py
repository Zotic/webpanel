import os
import subprocess
import json
import re
import socket
import time
import psutil
import urllib.request
import shlex
from datetime import datetime
from functools import wraps, lru_cache
from flask import Flask, render_template, request, jsonify, session, redirect, url_for

app = Flask(__name__)

# Безопасный ключ сессий
app.secret_key = os.getenv('PANEL_SECRET_KEY', os.urandom(24)) 
ADMIN_USERNAME = os.getenv('PANEL_ADMIN_USER', 'admin')
ADMIN_PASSWORD = os.getenv('PANEL_ADMIN_PASS', 'password')

SERVICE_PREFIX = "flaskbot_"
SYSTEMD_DIR = "/etc/systemd/system"
DEFAULT_DIR = "/root/Bots"
BOTS_ORDER_FILE = "bots_order.json"
LIMITS_FILE = "ip_limits.json"
CUSTOM_NAMES_FILE = "custom_names.json"

last_net_io = None
last_net_time = 0
ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

def clean_logs(logs_str):
    return ansi_escape.sub('', logs_str)

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
# УПРАВЛЕНИЕ СКОРОСТЬЮ (Traffic Control)
# ========================================
def get_limits():
    if os.path.exists(LIMITS_FILE):
        try:
            with open(LIMITS_FILE, 'r') as f: return json.load(f)
        except Exception as e: print(f"Error loading limits: {e}")
    return {}

def save_limits(limits):
    with open(LIMITS_FILE, 'w') as f: json.dump(limits, f)

def get_custom_names():
    if os.path.exists(CUSTOM_NAMES_FILE):
        try:
            with open(CUSTOM_NAMES_FILE, 'r') as f: return json.load(f)
        except Exception as e: print(f"Error loading custom names: {e}")
    return {}

def save_custom_names(names):
    with open(CUSTOM_NAMES_FILE, 'w') as f: json.dump(names, f)

def get_main_interface():
    try:
        out = run_command("ip route get 8.8.8.8")
        match = re.search(r'dev\s+([^\s]+)', out)
        if match: return match.group(1).strip()
    except: pass
    # Надежный фолбэк для вашего сервера
    return "enp3s0"

def sync_tc_rules():
    iface = get_main_interface()
    limits = get_limits()
    iface_safe = shlex.quote(iface)

    log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tc_debug.log")
    
    def do_tc(cmd):
        try:
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(f"CMD: {cmd}\n")
                if res.stderr: 
                    f.write(f"ERROR: {res.stderr.strip()}\n")
        except Exception as e:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(f"CRITICAL EXCEPTION: {str(e)}\n")

    with open(log_file, "w", encoding="utf-8") as f:
        f.write(f"--- ЗАПУСК СИНХРОНИЗАЦИИ в {datetime.now()} ---\n")
        f.write(f"Интерфейс: {iface}\nЗагружены лимиты: {limits}\n\n")

    # УДАЛЯЕМ старые правила
    do_tc(f"/sbin/tc qdisc del dev {iface_safe} root")
    do_tc(f"/sbin/tc qdisc del dev {iface_safe} ingress")

    if not limits:
        return

    # ИНИЦИАЛИЗАЦИЯ
    do_tc(f"/sbin/tc qdisc add dev {iface_safe} root handle 1: htb default 10")
    do_tc(f"/sbin/tc class add dev {iface_safe} parent 1: classid 1:1 htb rate 10000mbit")
    do_tc(f"/sbin/tc class add dev {iface_safe} parent 1:1 classid 1:10 htb rate 10000mbit")
    do_tc(f"/sbin/tc qdisc add dev {iface_safe} handle ffff: ingress")

    # ПРИМЕНЕНИЕ ПРАВИЛ
    for ip, data in limits.items():
        cid = str(data['class_id'])
        try: speed = str(int(data['speed']))
        except: continue

        ip_safe = shlex.quote(ip)
        cid_safe = shlex.quote(cid)
        speed_safe = shlex.quote(speed)

        # Download
        do_tc(f"/sbin/tc class add dev {iface_safe} parent 1:1 classid 1:{cid_safe} htb rate {speed_safe}mbit ceil {speed_safe}mbit burst 15k")
        if ':' in ip:
            do_tc(f"/sbin/tc filter add dev {iface_safe} protocol ipv6 parent 1:0 prio 1 u32 match ip6 dst {ip_safe} flowid 1:{cid_safe}")
        else:
            do_tc(f"/sbin/tc filter add dev {iface_safe} protocol ip parent 1:0 prio 1 u32 match ip dst {ip_safe}/32 flowid 1:{cid_safe}")

        # Upload
        if ':' in ip:
            do_tc(f"/sbin/tc filter add dev {iface_safe} parent ffff: protocol ipv6 prio 1 u32 match ip6 src {ip_safe} police rate {speed_safe}mbit burst 1m drop flowid :1")
        else:
            do_tc(f"/sbin/tc filter add dev {iface_safe} parent ffff: protocol ip prio 1 u32 match ip src {ip_safe}/32 police rate {speed_safe}mbit burst 1m drop flowid :1")

sync_tc_rules()

# ========================================
# ФУНКЦИИ ДЛЯ БОТОВ И СЕРВИСОВ
# ========================================
def get_saved_order():
    if os.path.exists(BOTS_ORDER_FILE):
        try:
            with open(BOTS_ORDER_FILE, 'r') as f: return json.load(f)
        except: pass
    return []

def save_bots_order(order_list):
    with open(BOTS_ORDER_FILE, 'w') as f: json.dump(order_list, f)

def get_exec_path(service_name, extract_python=False):
    try:
        svc_safe = shlex.quote(service_name)
        res = subprocess.run(f'systemctl show -p ExecStart {svc_safe}', shell=True, capture_output=True, text=True)
        path = ""
        match = re.search(r'argv\[\]=(.*?)\s+;', res.stdout)
        if match: path = match.group(1).strip()
        else:
            match_path = re.search(r'path=(.*?)\s+;', res.stdout)
            if match_path: path = match_path.group(1).strip()
                
        if path:
            is_python = False
            python_path = ""
            if extract_python:
                parts = path.split()
                if parts and 'python' in parts[0].lower():
                    is_python = True
                    python_path = parts[0]
                    if len(parts) > 1: path = " ".join(parts[1:])
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
            svc_safe = shlex.quote(service_name)
            
            status = run_command(f"systemctl is-active {svc_safe}")
            logs = run_command(f"journalctl -u {svc_safe} -n 15 --no-pager --output=cat")
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
# ФУНКЦИИ ДЛЯ VPN / ПРОКСИ / AMNEZIA
# ========================================
_proxy_pids_cache = set()
_proxy_pids_time = 0

def get_proxy_pids():
    global _proxy_pids_cache, _proxy_pids_time
    if time.time() - _proxy_pids_time > 15:
        pids = set()
        proxy_names = ['xray', '3proxy', 'danted']
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                name = proc.info['name'].lower()
                if any(p in name for p in proxy_names):
                    pids.add(proc.info['pid'])
            except: pass
        _proxy_pids_cache = pids
        _proxy_pids_time = time.time()
    return _proxy_pids_cache

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

    # 1. Сбор стандартных VPN-подключений
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

# 2. Сбор подключений AmneziaWG (через Docker)
    try:
        res = subprocess.run(['docker', 'exec', 'amnezia-awg2', 'awg', 'show', 'amn0', 'dump'], capture_output=True, text=True)
        if not res.stdout.strip():
            res = subprocess.run(['docker', 'exec', 'amnezia-awg2', 'awg', 'show', 'awg0', 'dump'], capture_output=True, text=True)
            
        lines = res.stdout.strip().split('\n')
        if len(lines) > 1:
            for line in lines[1:]:
                parts = line.split('\t')
                if len(parts) >= 8:
                    endpoint = parts[2]
                    latest_handshake = int(parts[4])
                    if latest_handshake > 0 and endpoint != "(none)":
                        diff = int(time.time()) - latest_handshake
                        if diff < 180:
                            real_ip = endpoint.split(':')[0]
                            inbound_ips[real_ip] = inbound_ips.get(real_ip, 0) + 1
    except: pass

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
                
                domain = dest_ip if skip_dns or not dest_ip.replace('.', '').isdigit() else reverse_dns(dest_ip)
                connections.append({
                    'time': time_str, 'client': client_ip, 'user': user,
                    'dest': f"{dest_ip}:{port}", 'domain': domain, 
                    'route': route, 'route_class': 'direct' if route == 'direct' else 'vless'
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
                time_str, qtype, domain, client = match.groups()
                key = f"{domain}:{client}"
                if key not in seen and not domain.startswith('in-addr.arpa'):
                    seen.add(key)
                    queries.append({'time': time_str, 'client': client, 'domain': domain, 'type': qtype})
        return queries[:50]
    except: return []

def analyze_proxy_logs():
    ip_to_users, target_to_users = {}, {}
    def add_user(ip, user):
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
            add_user(client_ip, user)
            if c['dest'] != 'ОШИБКА': add_target(c['dest'], client_ip, user)
    except: pass
    try:
        for c in get_danted_connections():
            client_ip, user = c['client'].split(':')[0], c['user']
            add_user(client_ip, user)
            if c['dest'] != 'unknown' and not str(c['dest']).startswith('Local:'): add_target(c['dest'], client_ip, user)
    except: pass
    try:
        for c in get_recent_connections(skip_dns=True):
            client_ip = c['client']
            user = c.get('user', '-')
            add_user(client_ip, user)
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

# --- AmneziaWG ---
def get_awg_status():
    try:
        # Проверяем статус Docker-контейнера
        res = run_command("docker inspect -f '{{.State.Status}}' amnezia-awg2")
        return "active" if "running" in res.lower() else "inactive"
    except:
        return "unknown"

def get_awg_metrics():
    data = []
    try:
        # Выполняем команду awg show ВНУТРИ контейнера
        # Пытаемся найти amn0, если нет - ищем стандартный awg0
        res = subprocess.run(['docker', 'exec', 'amnezia-awg2', 'awg', 'show', 'amn0', 'dump'], capture_output=True, text=True)
        if not res.stdout.strip():
            res = subprocess.run(['docker', 'exec', 'amnezia-awg2', 'awg', 'show', 'awg0', 'dump'], capture_output=True, text=True)
            
        lines = res.stdout.strip().split('\n')
        if not lines or len(lines) <= 1: return []
        
        for line in lines[1:]:
            parts = line.split('\t')
            if len(parts) >= 8:
                pubkey = parts[0][:8] + "..." 
                endpoint = parts[2] if parts[2] != "(none)" else "Оффлайн"
                allowed_ips = parts[3]
                latest_handshake = int(parts[4])
                transfer_rx = int(parts[5]) 
                transfer_tx = int(parts[6]) 
                
                if latest_handshake == 0:
                    last_seen = "Никогда"
                    is_online = False
                else:
                    diff = int(time.time()) - latest_handshake
                    is_online = diff < 180 
                    if diff < 60: last_seen = f"{diff} сек назад"
                    elif diff < 3600: last_seen = f"{diff // 60} мин назад"
                    elif diff < 86400: last_seen = f"{diff // 3600} часов назад"
                    else: last_seen = f"{diff // 86400} дней назад"

                def format_bytes(b):
                    if b > 1024**3: return f"{(b / 1024**3):.2f} GB"
                    elif b > 1024**2: return f"{(b / 1024**2):.2f} MB"
                    else: return f"{(b / 1024):.2f} KB"

                data.append({
                    'pubkey': pubkey, 'endpoint': endpoint, 'ips': allowed_ips,
                    'last_seen': last_seen, 'online': is_online,
                    'rx': format_bytes(transfer_rx), 'tx': format_bytes(transfer_tx)
                })
    except: pass
    return data

# --- MTProto (Docker) ---
def get_mtproto_status():
    try:
        res = run_command("docker inspect -f '{{.State.Status}}' mtprotoproxy-mtprotoproxy-1")
        return "active" if "running" in res.lower() else "inactive"
    except: return "unknown"

def get_mtproto_stats():
    stats = {
        "uptime_formatted": "0д 0ч 0м", 
        "active_connections": "0", 
        "total_connections": "0", 
        "traffic": "0 MB"
    }
    container_name = "mtprotoproxy-mtprotoproxy-1"
    
    try:
        started_at = run_command(f"docker inspect -f '{{{{.State.StartedAt}}}}' {container_name}")
        if started_at and not started_at.startswith('0001'):
            clean_time = started_at.split('.')[0].replace('T', ' ')
            dt = datetime.strptime(clean_time, "%Y-%m-%d %H:%M:%S")
            diff = int(datetime.utcnow().timestamp() - dt.timestamp())
            if diff > 0:
                m, s = divmod(diff, 60)
                h, m = divmod(m, 60)
                d, h = divmod(h, 24)
                stats['uptime_formatted'] = f"{d}д {h}ч {m}м"
    except: pass

    try:
        logs = run_command(f"docker logs --tail 100 {container_name}")
        last_tg_line = None
        for line in reversed(logs.split('\n')):
            if line.strip().startswith('tg:'):
                last_tg_line = line.strip()
                break
        
        if last_tg_line:
            match = re.search(r'tg:\s+(\d+)\s+connects\s+\((\d+)\s+current\),\s+([\d\.]+\s+[A-Za-z]+)', last_tg_line)
            if match:
                stats['total_connections'] = match.group(1)
                stats['active_connections'] = match.group(2)
                stats['traffic'] = match.group(3)
    except: pass
    
    return stats

# --- TLS Handshakes (Nginx Stream) ---
def get_tls_handshakes():
    log_file = '/var/log/nginx/stream_sni.log'
    if not os.path.exists(log_file): return []
    try:
        res = subprocess.run(['tail', '-n', '200', log_file], capture_output=True, text=True)
        raw_handshakes = []
        
        for line in reversed(res.stdout.split('\n')):
            if not line.strip(): continue
            parts = line.split(' | ')
            if len(parts) >= 3:
                time_str = parts[0].split(' ')[0] + ' ' + parts[0].split(' ')[1] 
                ip = parts[1].strip()
                
                # ПРОПУСКАЕМ ЛОКАЛЬНЫЕ АДРЕСА
                if ip in ('127.0.0.1', '::1', 'localhost'):
                    continue
                
                sni_raw = parts[2].replace('SNI: ', '').replace('"', '').strip()
                
                is_suspicious = (sni_raw == "" or sni_raw == "-")
                sni = sni_raw if not is_suspicious else "БЕЗ ДОМЕНА (IP Сканер)"
                target = parts[3].replace('To: ', '').strip() if len(parts) > 3 else "Сброшено"

                raw_handshakes.append({
                    'time': time_str, 'ip': ip, 'sni': sni,
                    'target': target, 'is_suspicious': is_suspicious, 'count': 1
                })

        grouped_handshakes = []
        for hs in raw_handshakes:
            if grouped_handshakes:
                last = grouped_handshakes[-1]
                if last['ip'] == hs['ip'] and last['sni'] == hs['sni']:
                    last['count'] += 1
                    last['time'] = hs['time']
                    continue
            grouped_handshakes.append(hs)

        return grouped_handshakes[:30]
    except: return []

# ========================================
# АНАЛИТИКА САЙТА И БЕЗОПАСНОСТИ
# ========================================
APP_START_TIME = time.time()

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
    humans, bots = set(), set()
    try:
        if os.path.exists('/var/log/nginx/access.log'):
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
                        if ip == '127.0.0.1': continue
                        if status_code.startswith('2'): humans.add(ip)
                        elif status_code == '301' or status_code.startswith(('4', '5')): bots.add(ip)
    except: pass
    pure_bots = bots - humans
    return {"total": len(humans) + len(pure_bots), "humans": len(humans), "bots": len(pure_bots)}

def parse_nginx_date(date_str):
    months = {'Jan':'01', 'Feb':'02', 'Mar':'03', 'Apr':'04', 'May':'05', 'Jun':'06', 'Jul':'07', 'Aug':'08', 'Sep':'09', 'Oct':'10', 'Nov':'11', 'Dec':'12'}
    try:
        parts = date_str.split('/')
        day = parts[0]
        month = months[parts[1]]
        year_time = parts[2].split(':')
        year = year_time[0]
        time_part = ":".join(year_time[1:])
        return f"{day}.{month}.{year} {time_part}"
    except: return date_str

def parse_syslog_date(date_str):
    try:
        m = re.match(r'^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})', date_str)
        if m:
            d = datetime.strptime(f"{datetime.now().year} {m.group(1)}", "%Y %b %d %H:%M:%S")
            return d.strftime("%d.%m.%Y %H:%M:%S")
    except: pass
    return date_str

@app.route('/api/site_analytics', methods=['GET'])
@login_required
def api_site_analytics():
    raw_logs = []

    def add_event(ip, time_str, source, severity, msg):
        color = "success"
        verdict = "Посетитель сайта / VPN"
        if severity == 2:
            color = "danger"
            verdict = "Сканер / Бот / Брутфорс"
        elif severity == 1:
            color = "warning"
            verdict = "Подозрительная активность"

        try:
            dt_obj = datetime.strptime(time_str, "%d.%m.%Y %H:%M:%S")
        except:
            dt_obj = datetime.now()

        raw_logs.append({
            "dt_obj": dt_obj, "time": time_str, "ip": ip,
            "source": source, "verdict": verdict, "color": color, "msg": msg
        })

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
                        if ip == '127.0.0.1': continue
                        time_str = parse_nginx_date(date_match.group(1))
                        req_type = "POST" if request_info.startswith('POST') else "GET"
                        desc = f"Запрос {req_type}: '{request_info}' (Ответ: {status_code})"
                        severity = 2 if status_code == '301' or status_code.startswith(('4', '5')) else 0
                        add_event(ip, time_str, "Nginx", severity, desc)
    except: pass

    try:
        res_xray_access = subprocess.run(['tail', '-n', '1000', '/var/log/xray/access.log'], capture_output=True, text=True)
        for line in res_xray_access.stdout.split('\n'):
            if not line.strip(): continue
            match = re.search(r'(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}).*?(?:from\s+)?([a-fA-F0-9\.:]+):\d+\s+accepted\s+[a-zA-Z0-9]+:([a-zA-Z0-9\.\-]+):(\d+)', line)
            if match:
                time_raw, client_ip, dest_ip, port = match.groups()
                date_part, time_part = time_raw.split()
                y, m, d = date_part.split('/')
                time_str = f"{d}.{m}.{y} {time_part}"
                user = ""
                email_match = re.search(r'email:\s*([^\s]+)', line)
                if email_match: user = f" (Юзер: {email_match.group(1)})"
                desc = f"Успешное VPN подключение к {dest_ip}:{port}{user}"
                add_event(client_ip, time_str, "Xray", 0, desc)
    except: pass

    try:
        res_xray_journal = subprocess.run(['journalctl', '-u', 'xray', '-n', '1000', '--no-pager'], capture_output=True, text=True)
        xray_sessions = {}
        for line in res_xray_journal.stdout.split('\n'):
            if not line.strip(): continue
            match = re.search(r'(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\.\d+\s+\[.*?\]\s+\[(\d+)\]\s+(.*)', line)
            if match:
                time_raw = match.group(1)
                date_part, time_part = time_raw.split()
                y, m, d = date_part.split('/')
                time_str = f"{d}.{m}.{y} {time_part}"
                conn_id = match.group(2)
                msg = match.group(3)
                if conn_id not in xray_sessions: xray_sessions[conn_id] = {"time": time_str, "ip": None, "messages": []}
                xray_sessions[conn_id]["messages"].append(msg)
                ip_match = re.search(r'->([\d\.]+):\d+', msg)
                if ip_match: xray_sessions[conn_id]["ip"] = ip_match.group(1)
                    
        for conn_id, s in xray_sessions.items():
            ip = s["ip"]
            if not ip: continue 
            full_msg = " ".join(s["messages"])
            if 'not look like a TLS handshake' in full_msg or 'invalid request version' in full_msg:
                add_event(ip, s["time"], "Xray", 2, "Ошибка TLS (Попытка не-VPN запроса или сканирования 443 порта)")
            elif 'fallback starts' in full_msg:
                sni_match = re.search(r'realName = ([^\s]+)', full_msg)
                sni = f" (Домен: {sni_match.group(1)})" if sni_match else ""
                add_event(ip, s["time"], "Xray", 1, f"Трафик не распознан VPN. Переброшен в Nginx (Fallback){sni}")
    except: pass

    try:
        res_ufw = subprocess.run(['journalctl', '-k', '--grep=UFW BLOCK', '-n', '200', '--no-pager'], capture_output=True, text=True)
        for line in res_ufw.stdout.split('\n'):
            if not line.strip(): continue
            src_m = re.search(r'SRC=([\d\.]+)', line)
            dpt_m = re.search(r'DPT=(\d+)', line)
            proto_m = re.search(r'PROTO=(\w+)', line)
            if src_m:
                ip = src_m.group(1)
                dpt = dpt_m.group(1) if dpt_m else "?"
                proto = proto_m.group(1) if proto_m else "TCP"
                time_str = parse_syslog_date(line)
                add_event(ip, time_str, "UFW", 2, f"Заблокирован вход на закрытый порт {dpt} ({proto})")
    except: pass

    try:
        res_ssh = subprocess.run(['tail', '-n', '500', '/var/log/auth.log'], capture_output=True, text=True)
        for line in res_ssh.stdout.split('\n'):
            if not line.strip(): continue
            if 'sshd' not in line: continue
            time_str = parse_syslog_date(line)
            if 'Failed password' in line:
                ip_m = re.search(r'from ([\d\.]+)', line)
                user_m = re.search(r'for (?:invalid user )?([^\s]+) from', line)
                if ip_m and user_m:
                    add_event(ip_m.group(1), time_str, "SSH", 2, f"Неудачный подбор пароля для пользователя '{user_m.group(1)}'")
            elif 'Connection closed by invalid user' in line or 'Invalid user' in line:
                ip_m = re.search(r'([\d\.]+)', line.split('from')[-1]) if 'from' in line else None
                user_m = re.search(r'user ([^\s]+)', line)
                if ip_m and user_m:
                    add_event(ip_m.group(1), time_str, "SSH", 2, f"Отклонен инвалидный пользователь: '{user_m.group(1)}'")
    except: pass

    raw_logs.sort(key=lambda x: x['dt_obj'])
    merged_logs = []
    for log in raw_logs:
        merged = False
        if merged_logs:
            last = merged_logs[-1]
            if last['ip'] == log['ip'] and last['source'] == log['source'] and last['verdict'] == log['verdict']:
                time_diff = (log['dt_obj'] - last['dt_obj']).total_seconds()
                if 0 <= time_diff <= 3:
                    if log['msg'] not in last['messages']: last['messages'].append(log['msg'])
                    last['dt_obj'] = log['dt_obj']
                    last['time'] = log['time']
                    merged = True
        if not merged:
            merged_logs.append({
                "dt_obj": log['dt_obj'], "time": log['time'], "ip": log['ip'],
                "source": log['source'], "verdict": log['verdict'],
                "color": log['color'], "messages": [log['msg']]
            })

    merged_logs.sort(key=lambda x: x['dt_obj'], reverse=True)
    for m in merged_logs: del m['dt_obj']
    return jsonify({"success": True, "logs": merged_logs[:150]})

# ========================================
# АНАЛИТИКА ДИСКА
# ========================================
def get_dir_size(path):
    total = 0
    try:
        for entry in os.scandir(path):
            try:
                if entry.is_symlink(): continue
                if entry.is_dir(follow_symlinks=False): total += get_dir_size(entry.path)
                else: total += entry.stat(follow_symlinks=False).st_size
            except: pass
    except: pass
    return total

@app.route('/api/disk_usage', methods=['POST'])
@login_required
def api_disk_usage():
    current_path = request.json.get('path', '/')
    if not os.path.isdir(current_path): current_path = '/'
    items = []
    if current_path != '/':
        items.append({"name": "..", "path": os.path.dirname(current_path), "type": "up", "size": -1})
    try:
        for entry in os.scandir(current_path):
            try:
                if entry.is_symlink(): continue
                if entry.is_dir(follow_symlinks=False):
                    items.append({"name": entry.name, "path": entry.path, "type": "dir", "size": get_dir_size(entry.path)})
                else:
                    items.append({"name": entry.name, "path": entry.path, "type": "file", "size": entry.stat(follow_symlinks=False).st_size})
            except: pass
    except Exception as e: return jsonify({"success": False, "error": str(e)})
    items.sort(key=lambda x: (x['type'] != 'up', x['size']), reverse=True)
    return jsonify({"success": True, "path": current_path, "items": items})

@app.route('/api/read_file', methods=['POST'])
@login_required
def api_read_file():
    file_path = request.json.get('path')
    if not file_path or not os.path.isfile(file_path):
        return jsonify({"success": False, "error": "Файл не найден или это директория"})
    try:
        if os.path.getsize(file_path) > 2 * 1024 * 1024:
            return jsonify({"success": False, "error": "Файл слишком большой (> 2 МБ)."})
        with open(file_path, 'r', encoding='utf-8') as f:
            return jsonify({"success": True, "content": f.read()})
    except UnicodeDecodeError: return jsonify({"success": False, "error": "Это бинарный файл."})
    except Exception as e: return jsonify({"success": False, "error": str(e)})

# ========================================
# МАРШРУТЫ САЙТА
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
def site_stats_page(): return redirect(url_for('index'))

@app.route('/bots')
@login_required
def bots(): return render_template('bots.html', bots=get_bots())

@app.route('/services')
@login_required
def system_services(): return render_template('services.html', services=get_all_services())

@app.route('/monitor')
@login_required
def system_monitor(): return render_template('monitor.html')

@app.route('/logs')
@login_required
def system_logs_page(): return render_template('logs.html')

@app.route('/vpn')
@login_required
def vpn():
    return render_template('vpn.html',
                           xray_status=run_command("systemctl is-active xray") == "active",
                           proxy_status=run_command("systemctl is-active 3proxy") == "active",
                           danted_status=run_command("systemctl is-active danted") == "active",
                           awg_status=(get_awg_status() == "active"),
                           mtproto_status=(get_mtproto_status() == "active"),
                           xray_connections=get_recent_connections(),
                           proxy_connections=get_3proxy_connections(),
                           danted_connections=get_danted_connections(),
                           awg_metrics=get_awg_metrics(),
                           mtproto_stats=get_mtproto_stats(),
                           dns_queries=get_dns_queries(),
                           tls_handshakes=get_tls_handshakes())

@app.route('/vpn_users')
@login_required
def vpn_users_page(): return render_template('vpn_users.html')

# ========================================
# НАСТРОЙКИ AMNEZIA WG (РЕДАКТОР)
# ========================================
def get_awg_config_path():
    # Ищем во всех возможных папках, которые создает установщик Amnezia
    paths = [
        '/opt/amnezia/amnezia-awg2/amn0.conf',
        '/opt/amnezia/amnezia-awg2/awg0.conf',
        '/opt/amnezia/awg2/wg0.conf',
        '/etc/amnezia/amneziawg/amn0.conf'
    ]
    for p in paths:
        if os.path.exists(p): return p
    return paths[0]

@app.route('/api/awg/get_config', methods=['GET'])
@login_required
def api_get_awg_config():
    path = get_awg_config_path()
    try:
        if not os.path.exists(path):
            return jsonify({"success": False, "error": f"Файл конфига не найден по пути: {path}"})
        with open(path, 'r', encoding='utf-8') as f:
            return jsonify({"success": True, "content": f.read(), "path": path})
    except Exception as e: return jsonify({"success": False, "error": str(e)})

@app.route('/api/awg/save_config', methods=['POST'])
@login_required
def api_save_awg_config():
    content = request.json.get('content')
    path = get_awg_config_path()
    if not content: return jsonify({"success": False, "error": "Пустой конфиг"})
    try:
        with open(path, 'w', encoding='utf-8') as f: f.write(content)
        # Так как это Docker, нам достаточно просто перезагрузить контейнер!
        # Внутренний скрипт Amnezia сам применит новые настройки при старте.
        run_command("docker restart amnezia-awg2")
        return jsonify({"success": True})
    except Exception as e: return jsonify({"success": False, "error": str(e)})

# ========================================
# API ОСНОВНЫЕ
# ========================================
@app.route('/api/get_service_file', methods=['POST'])
@login_required
def api_get_service_file():
    bot_name = request.json.get('bot_name')
    if not bot_name: return jsonify({"success": False, "error": "Имя бота не указано"})
    svc_name = f"{SERVICE_PREFIX}{bot_name}.service"
    file_path = os.path.join(SYSTEMD_DIR, svc_name)
    try:
        with open(file_path, 'r', encoding='utf-8') as f: return jsonify({"success": True, "content": f.read()})
    except Exception as e: return jsonify({"success": False, "error": str(e)})

@app.route('/api/save_service_file', methods=['POST'])
@login_required
def api_save_service_file():
    bot_name = request.json.get('bot_name')
    content = request.json.get('content')
    if not bot_name or content is None: return jsonify({"success": False, "error": "Нет данных"})
    svc_name = f"{SERVICE_PREFIX}{bot_name}.service"
    file_path = os.path.join(SYSTEMD_DIR, svc_name)
    try:
        with open(file_path, 'w', encoding='utf-8') as f: f.write(content)
        run_command("systemctl daemon-reload")
        return jsonify({"success": True})
    except Exception as e: return jsonify({"success": False, "error": str(e)})

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
    svc_name_safe = shlex.quote(svc_name)
    run_command(f"systemctl daemon-reload && systemctl enable {svc_name_safe} && systemctl start {svc_name_safe}")
    return jsonify({"success": True})

@app.route('/api/save_order', methods=['POST'])
@login_required
def update_order():
    save_bots_order(request.json.get('order', []))
    return jsonify({"success": True})

@app.route('/api/action', methods=['POST'])
@login_required
def bot_action():
    bot_name = request.json.get('bot_name')
    action = request.json.get('action')
    is_system = request.json.get('is_system', False)
    
    if not bot_name or not action: return jsonify({"success": False, "error": "Неверные параметры"})

    bot_name_safe = shlex.quote(bot_name)
    if is_system:
        svc_safe = bot_name_safe
        svc_raw = bot_name 
    else:
        svc_safe = shlex.quote(f"{SERVICE_PREFIX}{bot_name}.service")
        svc_raw = f"{SERVICE_PREFIX}{bot_name}.service"

    if action == "status_only": return jsonify({"success": True, "active": (run_command(f"systemctl is-active {svc_safe}") == "active")})
    if action == "restart": run_command(f"systemctl restart {svc_safe}")
    elif action == "start": run_command(f"systemctl start {svc_safe}")
    elif action == "stop": run_command(f"systemctl stop {svc_safe}")
    elif action == "delete":
        if is_system: return jsonify({"success": False, "error": "Удаление системных служб запрещено."})
        run_command(f"systemctl stop {svc_safe} && systemctl disable {svc_safe}")
        try: os.remove(os.path.join(SYSTEMD_DIR, svc_raw))
        except: pass
        run_command("systemctl daemon-reload")
        return jsonify({"success": True})
        
    is_active = (run_command(f"systemctl is-active {svc_safe}") == "active")
    n = 100 if action == "full_logs" else 15
    logs = run_command(f"journalctl -u {svc_safe} -n {n} --no-pager --output=cat")
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
    stats = {"cpu": {"percent": cpu_percent, "cores": cpu_cores, "load_avg": f"{round(load1, 2)} / {round(load5, 2)} / {round(load15, 2)}"}, "ram": {"percent": mem.percent, "used": mem.used, "total": mem.total}, "swap": {"percent": swap.percent, "used": swap.used, "total": swap.total}, "disk": {"percent": disk.percent, "used": disk.used, "total": disk.total}, "network": {"upload": upload_speed, "download": download_speed}}
    
    if 'proc_cache' not in globals(): global proc_cache; proc_cache = {}
    processes, current_pids = [], set()
    for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'memory_percent', 'memory_info']):
        try:
            pid = proc.info['pid']
            current_pids.add(pid)
            if pid not in proc_cache: proc_cache[pid] = proc; proc.cpu_percent(); cpu_usage = 0.0
            else: cpu_usage = proc_cache[pid].cpu_percent() / cpu_cores if cpu_cores > 0 else 0.0
            cmd = proc.info.get('cmdline')
            ram_mb = proc.info['memory_info'].rss / (1024 * 1024) if proc.info.get('memory_info') else 0
            processes.append({"pid": pid, "name": proc.info['name'], "path": " ".join(cmd) if cmd else proc.info.get('name', ''), "cpu": round(cpu_usage, 1), "ram_percent": round(proc.info['memory_percent'] or 0.0, 1), "ram_mb": round(ram_mb, 1)})
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
    
    lines_safe = shlex.quote(str(int(lines)))
    cmd = f"journalctl -r -n {lines_safe} -o json"
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
        final_users = [custom_names.get(u, u) for u in users_list]
        outbound_list.append({"ip": ip, "domain": domain if domain else "", "connections": count, "users": ", ".join(final_users) if final_users else "Неизвестно"})
    outbound_list.sort(key=lambda x: x['connections'], reverse=True)
    return jsonify({"success": True, "inbound": inbound_list, "outbound": outbound_list})

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

@app.route('/api/set_custom_name', methods=['POST'])
@login_required
def api_set_custom_name():
    ip = request.json.get('ip')
    name = request.json.get('name')
    names = get_custom_names()
    if not name or name.strip() == "":
        if ip in names: del names[ip]
    else: names[ip] = name.strip()
    save_custom_names(names)
    return jsonify({"success": True})

@app.route('/api/ip_info/<ip>', methods=['GET'])
@login_required
def ip_info(ip):
    try:
        url = f"https://ipinfo.io/{ip}/json"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'Accept': 'application/json'})
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode())
            if data.get('bogon'): return jsonify({"success": False, "error": "Локальный IP адрес"})
            return jsonify({"success": True, "data": data})
    except Exception as e: return jsonify({"success": False, "error": str(e)})

@app.route('/api/vpn/action', methods=['POST'])
@login_required
def api_vpn_action():
    service = request.json.get('service')
    action = request.json.get('action') 
    
    if service not in ['xray', '3proxy', 'danted', 'awg', 'mtproto']:
        return jsonify({"success": False, "error": "Неизвестный сервис"})
    if action not in ['start', 'stop', 'restart']:
        return jsonify({"success": False, "error": "Неизвестное действие"})

    try:
        if service in ['xray', '3proxy', 'danted']: 
            svc_safe = shlex.quote(service)
            action_safe = shlex.quote(action)
            run_command(f"systemctl {action_safe} {svc_safe}")
            
        elif service == 'awg':
            container_safe = shlex.quote("amnezia-awg2")
            action_safe = shlex.quote(action)
            run_command(f"docker {action_safe} {container_safe}")
            
        elif service == 'mtproto': 
            container_safe = shlex.quote("mtprotoproxy-mtprotoproxy-1")
            action_safe = shlex.quote(action)
            run_command(f"docker {action_safe} {container_safe}")
            
        return jsonify({"success": True})
    except Exception as e: return jsonify({"success": False, "error": str(e)})

import shutil
import zipfile
from werkzeug.utils import secure_filename
from flask import send_file, request

# ========================================
# ZX EXPLORER (ВЕБ-ПРОВОДНИК)
# ========================================

@app.route('/explorer')
@login_required
def explorer_page():
    return render_template('explorer.html')

@app.route('/api/explorer/list', methods=['POST'])
@login_required
def api_explorer_list():
    target_path = request.json.get('path', '/')
    if not os.path.exists(target_path) or not os.path.isdir(target_path):
        target_path = '/'

    items = []
    try:
        for entry in os.scandir(target_path):
            try:
                stat = entry.stat(follow_symlinks=False)
                mtime = datetime.fromtimestamp(stat.st_mtime).strftime('%d.%m.%Y %H:%M')
                items.append({
                    "name": entry.name,
                    "path": entry.path,
                    "is_dir": entry.is_dir(follow_symlinks=False),
                    "size": stat.st_size if not entry.is_dir(follow_symlinks=False) else 0,
                    "mtime": mtime
                })
            except: pass
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

    # Сортируем: сначала папки, потом файлы, по алфавиту
    items.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))
    
    # Формируем хлебные крошки (Breadcrumbs)
    parts = target_path.strip('/').split('/')
    breadcrumbs = [{"name": "Root", "path": "/"}]
    current = ""
    if target_path != '/':
        for part in parts:
            if part:
                current += "/" + part
                breadcrumbs.append({"name": part, "path": current})

    return jsonify({"success": True, "path": target_path, "items": items, "breadcrumbs": breadcrumbs})

@app.route('/api/explorer/operate', methods=['POST'])
@login_required
def api_explorer_operate():
    data = request.json
    action = data.get('action')
    paths = data.get('paths', [])
    dest = data.get('dest', '')
    new_name = data.get('new_name', '')

    try:
        if action == 'delete':
            for p in paths:
                if os.path.isdir(p): shutil.rmtree(p, ignore_errors=True)
                else: os.remove(p)
                
        elif action == 'create_folder':
            os.makedirs(os.path.join(dest, new_name), exist_ok=True)
            
        elif action == 'create_file':
            with open(os.path.join(dest, new_name), 'w') as f: pass
            
        elif action == 'rename':
            os.rename(paths[0], os.path.join(os.path.dirname(paths[0]), new_name))
            
        elif action == 'copy' or action == 'cut':
            for p in paths:
                name = os.path.basename(p)
                target = os.path.join(dest, name)
                # Если файл существует, добавляем суффикс
                if os.path.exists(target):
                    target = os.path.join(dest, "copy_" + name)
                
                if action == 'copy':
                    if os.path.isdir(p): shutil.copytree(p, target)
                    else: shutil.copy2(p, target)
                elif action == 'cut':
                    shutil.move(p, target)
                    
        elif action == 'zip':
            zip_path = os.path.join(dest, new_name if new_name.endswith('.zip') else new_name + '.zip')
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for p in paths:
                    if os.path.isdir(p):
                        for root, dirs, files in os.walk(p):
                            for file in files:
                                file_path = os.path.join(root, file)
                                arcname = os.path.relpath(file_path, os.path.dirname(p))
                                zipf.write(file_path, arcname)
                    else:
                        zipf.write(p, os.path.basename(p))
                        
        elif action == 'unzip':
            for p in paths:
                extract_dir = os.path.join(dest, os.path.basename(p).replace('.zip', ''))
                os.makedirs(extract_dir, exist_ok=True)
                with zipfile.ZipFile(p, 'r') as zipf:
                    zipf.extractall(extract_dir)

        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/explorer/upload', methods=['POST'])
@login_required
def api_explorer_upload():
    dest = request.form.get('dest', '/')
    if 'files[]' not in request.files:
        return jsonify({"success": False, "error": "Нет файлов"})
    
    files = request.files.getlist('files[]')
    try:
        for file in files:
            if file.filename:
                # secure_filename удаляет русские буквы, поэтому используем оригинальное имя, но защищаем от ../
                filename = os.path.basename(file.filename) 
                file.save(os.path.join(dest, filename))
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/explorer/download', methods=['GET'])
@login_required
def api_explorer_download():
    path = request.args.get('path')
    if path and os.path.isfile(path):
        return send_file(path, as_attachment=True)
    return "Файл не найден", 404

# Улучшенное сохранение текста (Save / Save As)
@app.route('/api/explorer/save_text', methods=['POST'])
@login_required
def api_explorer_save_text():
    path = request.json.get('path')
    content = request.json.get('content')
    try:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

# ========================================
# СТАТИСТИКА ТРАФИКА СЕРВЕРА (VNSTAT)
# ========================================
import shutil

@app.route('/api/network_traffic', methods=['POST'])
@login_required
def api_network_traffic():
    start_date_str = request.json.get('start_date') # YYYY-MM-DD
    end_date_str = request.json.get('end_date')     # YYYY-MM-DD

    # Проверяем, установлена ли утилита
    if shutil.which("vnstat") is None:
        return jsonify({"success": False, "error": "Утилита vnstat не установлена. Выполните 'apt install vnstat' в консоли."})

    iface = get_main_interface()

    try:
        # Получаем данные за все дни в формате JSON
        res = subprocess.run(f"vnstat -i {iface} --json", shell=True, capture_output=True, text=True)
        
        # Если vnstat только что установлен, ему нужна минута на создание БД
        if not res.stdout.strip():
            return jsonify({"success": False, "error": "vnstat собирает первые данные. Подождите пару минут."})
            
        data = json.loads(res.stdout)

        iface_data = None
        for interface in data.get('interfaces', []):
            if interface.get('name') == iface:
                iface_data = interface
                break

        if not iface_data:
            return jsonify({"success": False, "error": f"Нет данных для интерфейса {iface}"})

        days = iface_data.get('traffic', {}).get('day', [])

        rx_total = 0
        tx_total = 0

        # Преобразуем строки в объекты дат для сравнения
        start_dt = datetime.strptime(start_date_str, "%Y-%m-%d").date() if start_date_str else datetime.min.date()
        end_dt = datetime.strptime(end_date_str, "%Y-%m-%d").date() if end_date_str else datetime.max.date()

        for day in days:
            d = day.get('date', {})
            current_dt = datetime(d.get('year'), d.get('month'), d.get('day')).date()

            # Суммируем трафик за те дни, которые попадают в выбранный диапазон
            if start_dt <= current_dt <= end_dt:
                rx_total += day.get('rx', 0)
                tx_total += day.get('tx', 0)

        return jsonify({
            "success": True,
            "rx": rx_total,   # Скачано
            "tx": tx_total,   # Отправлено
            "total": rx_total + tx_total
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

# ========================================
# FAIL2BAN (ЗАЩИТА ОТ БРУТФОРСА)
# ========================================
import shutil

def get_fail2ban_status():
    if shutil.which("fail2ban-client") is None:
        return {"status": "not_installed", "jails": {}}
    
    try:
        # Проверяем, запущен ли демон
        res = run_command("fail2ban-client ping")
        if "Server replied: pong" not in res:
            return {"status": "inactive", "jails": {}}

        # Получаем список активных "тюрем" (jails)
        jails_raw = run_command("fail2ban-client status")
        match = re.search(r'Jail list:\s+(.*)', jails_raw)
        if not match:
            return {"status": "active", "jails": {}}
            
        jail_list = [j.strip() for j in match.group(1).split(',')]
        jails_info = {}

        # Получаем статистику по каждой тюрьме
        for jail in jail_list:
            info = run_command(f"fail2ban-client status {shlex.quote(jail)}")
            
            failed_total = 0
            banned_currently = 0
            banned_total = 0
            banned_ips = []

            m_fail = re.search(r'Total failed:\s+(\d+)', info)
            m_banned_curr = re.search(r'Currently banned:\s+(\d+)', info)
            m_banned_tot = re.search(r'Total banned:\s+(\d+)', info)
            m_ips = re.search(r'Banned IP list:\s+(.*)', info)

            if m_fail: failed_total = int(m_fail.group(1))
            if m_banned_curr: banned_currently = int(m_banned_curr.group(1))
            if m_banned_tot: banned_total = int(m_banned_tot.group(1))
            if m_ips and m_ips.group(1):
                banned_ips = [ip.strip() for ip in m_ips.group(1).split() if ip.strip()]

            jails_info[jail] = {
                "failed_total": failed_total,
                "banned_currently": banned_currently,
                "banned_total": banned_total,
                "banned_ips": banned_ips
            }
            
        return {"status": "active", "jails": jails_info}
    except:
        return {"status": "error", "jails": {}}

@app.route('/api/fail2ban/get_stats', methods=['GET'])
@login_required
def api_f2b_stats():
    return jsonify({"success": True, "data": get_fail2ban_status()})

@app.route('/api/fail2ban/unban', methods=['POST'])
@login_required
def api_f2b_unban():
    ip = request.json.get('ip')
    jail = request.json.get('jail')
    if not ip or not jail: return jsonify({"success": False, "error": "Нет данных"})
    
    try:
        ip_safe = shlex.quote(ip)
        jail_safe = shlex.quote(jail)
        res = run_command(f"fail2ban-client set {jail_safe} unbanip {ip_safe}")
        
        # fail2ban-client возвращает '1', если разбан успешен, и '0', если IP не было в бане
        if res.strip() == "1":
            return jsonify({"success": True})
        else:
            return jsonify({"success": False, "error": f"IP {ip} не найден в тюрьме {jail}."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/fail2ban/ban', methods=['POST'])
@login_required
def api_f2b_ban():
    ip = request.json.get('ip')
    jail = request.json.get('jail')
    if not ip or not jail: return jsonify({"success": False, "error": "Нет данных"})
    
    try:
        ip_safe = shlex.quote(ip)
        jail_safe = shlex.quote(jail)
        run_command(f"fail2ban-client set {jail_safe} banip {ip_safe}")
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

if __name__ == '__main__':
    # ОПТИМИЗАЦИЯ И БЕЗОПАСНОСТЬ: Флаг debug отключен для Production
    app.run(host='0.0.0.0', port=5000, debug=False)
