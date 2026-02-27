import os
import subprocess
import json
import re
import socket
import psutil
from datetime import datetime
from functools import wraps, lru_cache
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import time

# Глобальные переменные для расчета скорости сети
last_net_io = None
last_net_time = 0

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'fallback_secret_key_if_not_set')

# === НАСТРОЙКИ АВТОРИЗАЦИИ ===
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'default_password')

# === НАСТРОЙКИ БОТОВ ===
SERVICE_PREFIX = "flaskbot_"
SYSTEMD_DIR = "/etc/systemd/system"
DEFAULT_DIR = "/root/Bots"
BOTS_ORDER_FILE = "bots_order.json" # Файл для сохранения порядка ботов

# ========================================
# Вспомогательные функции для порядка ботов
# ========================================
def get_saved_order():
    if os.path.exists(BOTS_ORDER_FILE):
        try:
            with open(BOTS_ORDER_FILE, 'r') as f:
                return json.load(f)
        except:
            return []
    return []

def save_bots_order(order_list):
    with open(BOTS_ORDER_FILE, 'w') as f:
        json.dump(order_list, f)

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
# ФУНКЦИИ ДЛЯ БОТОВ И СЕРВИСОВ
# ========================================
def get_exec_path(service_name, extract_python=False):
    """ Вспомогательная функция для получения пути ExecStart """
    try:
        res = subprocess.run(['systemctl', 'show', '-p', 'ExecStart', service_name], capture_output=True, text=True)
        path = ""
        # Пытаемся получить полную команду с аргументами
        match = re.search(r'argv\[\]=(.*?)\s+;', res.stdout)
        if match:
            path = match.group(1).strip()
        else:
            # Иначе берем просто путь к исполняемому файлу
            match_path = re.search(r'path=(.*?)\s+;', res.stdout)
            if match_path:
                path = match_path.group(1).strip()
                
        if path:
            is_python = False
            python_path = ""
            
            # Если просят вырезать python (только для ботов)
            if extract_python:
                parts = path.split()
                if parts and 'python' in parts[0].lower():
                    is_python = True
                    python_path = parts[0] # Сохраняем оригинальный путь к интерпретатору (напр. /usr/bin/python3)
                    
                    # Убираем путь к интерпретатору из основной строки
                    if len(parts) > 1:
                        path = " ".join(parts[1:])
                        
            return path, is_python, python_path
            
    except:
        pass
    return "Путь неизвестен", False, ""

def get_bots():
    bots = []
    if not os.path.exists(SYSTEMD_DIR):
        return bots
        
    for file in os.listdir(SYSTEMD_DIR):
        if file.startswith(SERVICE_PREFIX) and file.endswith(".service"):
            bot_name = file[len(SERVICE_PREFIX):-8]
            service_name = file
            status = run_command(f"systemctl is-active {service_name}")
            logs = run_command(f"journalctl -u {service_name} -n 15 --no-pager --output=cat")
            
            exec_path, is_python, python_path = get_exec_path(service_name, extract_python=True) 
            
            bots.append({
                "name": bot_name, 
                "service": service_name,
                "active": (status == "active"), 
                "path": exec_path, 
                "is_python": is_python,
                "python_path": python_path,
                "logs": clean_logs(logs)
            })
            
    # Сортируем ботов согласно сохраненному списку
    saved_order = get_saved_order()
    def sort_key(bot):
        try:
            return saved_order.index(bot['name'])
        except ValueError:
            return 999999 # Новые боты (которых нет в файле) будут в самом конце списка
            
    bots.sort(key=sort_key)
    return bots

def get_all_services():
    try:
        # 1. Быстро получаем только имена всех сервисов
        res = subprocess.run(['systemctl', 'list-units', '--type=service', '--all', '--no-pager', '--no-legend'], capture_output=True, text=True)
        service_names = []
        for line in res.stdout.split('\n'):
            if not line.strip(): continue
            parts = line.split()
            if parts and parts[0].endswith('.service'):
                service_names.append(parts[0])
                
        if not service_names:
            return []

        # 2. Выгружаем свойства для всех найденных сервисов ОДНОЙ командой (очень быстро)
        cmd = ['systemctl', 'show', '-p', 'Id,ActiveState,ExecStart'] + service_names
        res2 = subprocess.run(cmd, capture_output=True, text=True)
        
        services = []
        current_svc = {}
        
        lines = res2.stdout.split('\n')
        lines.append('') # Чтобы гарантированно обработать последний блок
        
        for line in lines:
            line = line.strip()
            if not line:
                if 'Id' in current_svc and current_svc['Id'].endswith('.service'):
                    path_raw = current_svc.get('ExecStart', '')
                    clean_path = ""
                    
                    match_argv = re.search(r'argv\[\]=(.*?)\s+;', path_raw)
                    if match_argv:
                        clean_path = match_argv.group(1).strip()
                    else:
                        match_path = re.search(r'path=(.*?)\s+;', path_raw)
                        if match_path:
                            clean_path = match_path.group(1).strip()

                    services.append({
                        "name": current_svc['Id'],
                        "service": current_svc['Id'],
                        "active": (current_svc.get('ActiveState') == 'active'),
                        "path": clean_path,
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
# ФУНКЦИИ ДЛЯ XRAY / VPN
# ========================================
def get_xray_status():
    try:
        res = subprocess.run(['systemctl', 'is-active', 'xray'], capture_output=True, text=True)
        return "active" if res.stdout.strip() == "active" else "inactive"
    except:
        return "unknown"

def get_direct_domains():
    try:
        with open('/etc/xray/config.json', 'r') as f:
            config = json.load(f)
        all_domains = []
        for rule in config['routing']['rules']:
            if rule.get('outboundTag') == 'direct' and 'domain' in rule:
                for d in rule['domain']:
                    if d.startswith('domain:'):
                        all_domains.append(d.replace('domain:', ''))
                    elif not d.startswith('geosite:') and not d.startswith('apt.') and not d.startswith('archive.'):
                        all_domains.append(d)
        return all_domains
    except:
        return []

@lru_cache(maxsize=1000)
def reverse_dns(ip):
    try:
        if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
            return None
        socket.setdefaulttimeout(0.2)
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname if hostname != ip else None
    except:
        return None

def get_recent_connections():
    try:
        result = subprocess.run(['tail', '-100', '/var/log/xray/access.log'], capture_output=True, text=True)
        connections = []
        seen = set()
        for line in result.stdout.split('\n'):
            # Более гибкая регулярка: учитывает IPv6, разные протоколы и пробелы
            match = re.search(r'(\d{2}:\d{2}:\d{2}).*?(?:from\s+)?([a-fA-F0-9\.:]+):\d+\s+accepted\s+[a-zA-Z0-9]+:([a-zA-Z0-9\.\-]+):(\d+)\s+\[([^\]]+)\]', line)
            if match:
                time, client, dest_ip, port, route = match.groups()
                key = f"{dest_ip}:{port}:{route}"
                if key in seen: continue
                seen.add(key)
                domain = dest_ip if not dest_ip.replace('.', '').isdigit() else reverse_dns(dest_ip)
                connections.append({
                    'time': time, 'client': client, 'dest': f"{dest_ip}:{port}",
                    'domain': domain, 'route': route, 'route_class': 'direct' if route == 'direct' else 'vless'
                })
        connections.reverse()
        return connections[:50]
    except Exception as e:
        print("Ошибка чтения логов Xray:", e)
        return []

def get_dns_queries():
    try:
        result = subprocess.run(['tail', '-200', '/var/log/dnsmasq.log'], capture_output=True, text=True)
        queries = []
        seen = set()
        for line in result.stdout.split('\n'):
            match = re.search(r'(\d{2}:\d{2}:\d{2}).*query\[(\w+)\] ([^\s]+) from ([\d.]+)', line)
            if match:
                time, qtype, domain, client = match.groups()
                key = f"{domain}:{client}"
                if key not in seen and not domain.startswith('in-addr.arpa'):
                    seen.add(key)
                    queries.append({'time': time, 'client': client, 'domain': domain, 'type': qtype})
        return queries[:50]
    except:
        return []

# ========================================
# УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ И СКОРОСТЬЮ (Traffic Control)
# ========================================
LIMITS_FILE = "ip_limits.json"

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
    """Определяем главный сетевой интерфейс, смотрящий в интернет"""
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

    # Сбрасываем все текущие ограничения
    run_command(f"tc qdisc del dev {iface} root")

    if not limits:
        return # Если файла нет или он пуст - оставляем интернет свободным

    # Создаем базовое дерево классов
    run_command(f"tc qdisc add dev {iface} root handle 1: htb default 10")
    run_command(f"tc class add dev {iface} parent 1: classid 1:10 htb rate 1000mbit")

    # Применяем лимиты по IP адресам
    for ip, data in limits.items():
        cid = data['class_id']
        speed = data['speed']
        run_command(f"tc class add dev {iface} parent 1: classid 1:{cid} htb rate {speed}mbit")
        run_command(f"tc filter add dev {iface} protocol ip parent 1:0 prio 1 u32 match ip dst {ip}/32 flowid 1:{cid}")

# При запуске сервера сразу синхронизируем правила
sync_tc_rules()

def get_active_vpn_users_DELETE():
    """Ищет IP подключенных пользователей и разделяет их на входящие/исходящие соединения"""
    proxy_names = ['xray', '3proxy', 'danted', 'shadowbox']
    proxy_pids = set()
    
    # Находим PID процессов наших прокси
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] in proxy_names:
                proxy_pids.add(proc.info['pid'])
        except: pass

    active_ips = {}
    
    # Чтобы отличить локальный IP сервера от IP клиента
    # Получаем локальные IP адреса машины
    local_ips = set()
    for interface, snics in psutil.net_if_addrs().items():
        for snic in snics:
            if snic.family == socket.AF_INET:
                local_ips.add(snic.address)

    # Проходим по всем TCP соединениям
    for conn in psutil.net_connections(kind='tcp'):
        if conn.status == 'ESTABLISHED' and conn.pid in proxy_pids:
            if conn.laddr and conn.raddr:
                remote_ip = conn.raddr.ip
                
                # Игнорируем внутренние системные соединения сервера (напр. 127.0.0.1)
                if remote_ip in local_ips or remote_ip.startswith('127.'):
                    continue

                if remote_ip not in active_ips:
                    active_ips[remote_ip] = {"inbound": 0, "outbound": 0}
                
                # Если удаленный порт высокий (динамический порт клиента), 
                # а локальный порт стандартный для прокси (443, 80, 2408 и тд) -> это ВХОДЯЩЕЕ от клиента
                # В противном случае -> это ИСХОДЯЩЕЕ от прокси в интернет
                if conn.raddr.port > 10240 and conn.laddr.port < 10240:
                    active_ips[remote_ip]["inbound"] += 1
                else:
                    active_ips[remote_ip]["outbound"] += 1

    return active_ips

# ========================================
# МАРШРУТЫ (Сайт)
# ========================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form.get('username') == ADMIN_USERNAME and request.form.get('password') == ADMIN_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('bots'))
        error = "Неверный логин или пароль"
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return redirect(url_for('bots'))

@app.route('/bots')
@login_required
def bots():
    return render_template('bots.html', bots=get_bots())

# НОВЫЙ МАРШРУТ ДЛЯ СЕРВИСОВ
@app.route('/services')
@login_required
def system_services():
    return render_template('services.html', services=get_all_services())

def get_3proxy_connections():
    # 3proxy может хранить логи по разным путям в зависимости от настроек
    possible_paths = [
        '/var/log/3proxy.log', 
        '/var/log/3proxy/3proxy.log', 
        '/var/log/3proxy'
    ]
    
    log_file = None
    for path in possible_paths:
        if os.path.isfile(path): # Проверяем, что это именно файл, а не папка
            log_file = path
            break
            
    if not log_file:
        # Если файл не найден, выводим это прямо в таблицу на сайте
        return [{"time": "-", "user": "-", "client": "-", "dest": "ОШИБКА", "status": "Файл лога 3proxy не найден"}]

    try:
        res = subprocess.run(['tail', '-100', log_file], capture_output=True, text=True)
        connections = []
        
        for line in reversed(res.stdout.split('\n')):
            if not line.strip(): continue
            parts = line.split()
            
            # В стандартном логе 3proxy 10 колонок
            if len(parts) >= 10:
                try:
                    dt = datetime.fromtimestamp(float(parts[0]))
                    time_str = dt.strftime('%d.%m %H:%M:%S')
                except:
                    time_str = parts[0]
                
                user = parts[3]
                event = parts[9]
                
                # Очищаем технические логи (например Accepting_connections)
                if 'Accepting_connections' in event:
                    continue
                    
                # Убираем дублирование IP в статусе (CONNECT_1.1.1.1:80 -> CONNECT)
                if event.startswith('CONNECT_'):
                    event = 'CONNECT'
                elif event.startswith('UNKNOWN_'):
                    event = 'UNKNOWN'

                connections.append({
                    'time': time_str,
                    'user': user if user != '-' else 'Unknown',
                    'client': parts[4],
                    'dest': parts[5],
                    'status': event
                })
                
        return connections[:50]
    except Exception as e:
        print("Ошибка парсинга логов 3proxy:", e)
        return [{"time": "-", "user": "-", "client": "-", "dest": "ОШИБКА", "status": str(e)}]

def get_danted_connections():
    try:
        # Читаем логи danted
        res = subprocess.run(['tail', '-100', '/var/log/socks.log'], capture_output=True, text=True)
        connections = []
        for line in reversed(res.stdout.split('\n')):
            if not line.strip(): continue
            
            # Извлекаем время
            time_match = re.search(r'^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})', line)
            time_str = time_match.group(1) if time_match else ""
            
            # Определяем статус (пропущен/заблокирован)
            status = "pass" if "pass(" in line else "block" if "block(" in line else "info"
            
            client, dest, user = "unknown", "unknown", "-"
            
            # Ищем юзернейм: username%ИМЯ@
            user_m = re.search(r'username%([^@\s]+)@', line)
            if user_m: 
                user = user_m.group(1)
            
            # Парсим логи КОННЕКТОВ (когда идет запрос к сайту)
            if "tcp/connect" in line:
                # 1. Достаем IP клиента (тот что после @)
                client_m = re.search(r'@(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.\d+', line)
                if client_m:
                    client = client_m.group(1)

                # 2. Достаем финальную ЦЕЛЬ (IP сайта). 
                # Danted пишет цепочку вида: "-> 45.85.117.150.53210 35.83.208.188.10443"
                # Нам нужна вторая часть (целевой IP и порт, разделенные точкой)
                dest_m = re.search(r'->\s+[\d\.]+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d+)', line)
                if dest_m:
                    dest = f"{dest_m.group(1)}:{dest_m.group(2)}"

            # Парсим логи ВХОДЯЩИХ запросов (до того как сформирована цель)
            elif "tcp/accept" in line:
                m = re.search(r'[:\]]\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.\d+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if m:
                    client = m.group(1)
                    dest = f"Local: {m.group(2)}"

            # Добавляем только если удалось извлечь хотя бы IP клиента
            if client != "unknown":
                raw_log = line.split(']: ')[-1] if ']: ' in line else line
                # Убираем юзернейм из лога для компактности
                if user != "-":
                    raw_log = re.sub(r'username%[^@]+@', '', raw_log)

                connections.append({
                    'time': time_str, 
                    'client': client, 
                    'dest': dest, 
                    'user': user, 
                    'status': status,
                    'raw': raw_log
                })
        return connections[:50]
    except Exception as e:
        print("Ошибка danted:", e)
        return []

def get_outline_status():
    """Проверяет, запущен ли Docker-контейнер Outline (shadowbox)"""
    try:
        res = subprocess.run(['docker', 'ps', '--filter', 'name=shadowbox', '--format', '{{.Status}}'], capture_output=True, text=True)
        return "active" if "Up" in res.stdout else "inactive"
    except:
        return "unknown"

def get_outline_metrics():
    """Собирает имена пользователей из БД Outline и трафик из Prometheus"""
    data = []
    keys_info = {}
    
    # 1. Достаем имена ключей из конфигурации Outline
    config_path = '/opt/outline/persisted-state/shadowbox_config.json'
    try:
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = json.load(f)
                
                # Ищем массив ключей (accessKeys для новых версий, keys для старых)
                keys_list = config.get('accessKeys', config.get('keys', []))
                
                for k in keys_list:
                    kid = str(k.get('id'))
                    name = k.get('name')
                    keys_info[kid] = name if name else f"Без имени (ID: {kid})"
    except Exception as e:
        print("Outline config error:", e)

    # 2. Ищем правильное имя контейнера Outline (обычно shadowbox)
    container_name = "shadowbox"
    try:
        res = subprocess.run(['docker', 'ps', '--format', '{{.Names}}'], capture_output=True, text=True)
        if 'shadowbox' not in res.stdout:
            res2 = subprocess.run(['docker', 'ps', '--filter', 'ancestor=quay.io/outline/shadowbox', '--format', '{{.Names}}'], capture_output=True, text=True)
            if res2.stdout.strip():
                container_name = res2.stdout.strip().split('\n')[0]
    except: pass

    # 3. Вытаскиваем статистику трафика из Prometheus внутри найденного контейнера
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
                    try:
                        val = float(line.split()[-1])
                        metrics_dict[kid] = metrics_dict.get(kid, 0) + val
                    except: pass
    except Exception as e:
        print("Outline metrics error:", e)

    # 4. Формируем список для HTML
    for kid, bytes_total in metrics_dict.items():
        name = keys_info.get(kid, f"Неизвестный ключ (ID: {kid})")
        
        if bytes_total > 1024**3:
            usage = f"{(bytes_total / 1024**3):.2f} GB"
        else:
            usage = f"{(bytes_total / 1024**2):.2f} MB"

        data.append({
            'id': kid,
            'name': name,
            'usage': usage,
            'raw_bytes': bytes_total
        })

    data.sort(key=lambda x: x['raw_bytes'], reverse=True)
    return data

@app.route('/api/outline/reset', methods=['POST'])
@login_required
def reset_outline_stats():
    # Находим имя контейнера
    container_name = "shadowbox"
    try:
        res = subprocess.run(['docker', 'ps', '--format', '{{.Names}}'], capture_output=True, text=True)
        if 'shadowbox' not in res.stdout:
            res2 = subprocess.run(['docker', 'ps', '--filter', 'ancestor=quay.io/outline/shadowbox', '--format', '{{.Names}}'], capture_output=True, text=True)
            if res2.stdout.strip():
                container_name = res2.stdout.strip().split('\n')[0]
                
        # Перезапускаем контейнер (это обнулит счетчики Prometheus, ключи и пользователи останутся!)
        subprocess.run(['docker', 'restart', container_name])
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/vpn')
@login_required
def vpn():
    return render_template('vpn.html',
                           xray_status=run_command("systemctl is-active xray") == "active",
                           proxy_status=run_command("systemctl is-active 3proxy") == "active",
                           danted_status=run_command("systemctl is-active danted") == "active",
                           outline_status=(get_outline_status() == "active"),
                           xray_connections=get_recent_connections(),
                           proxy_connections=get_3proxy_connections(),
                           danted_connections=get_danted_connections(),
                           outline_metrics=get_outline_metrics(),
                           dns_queries=get_dns_queries())

@app.route('/monitor')
@login_required
def system_monitor():
    return render_template('monitor.html')

# ========================================
# API БОТОВ И СЕРВИСОВ
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

@app.route('/api/action', methods=['POST'])
@login_required
def bot_action():
    bot_name = request.json.get('bot_name')
    action = request.json.get('action')
    is_system = request.json.get('is_system', False)
    
    svc = bot_name if is_system else f"{SERVICE_PREFIX}{bot_name}.service"
    
    # Легкий запрос только для обновления статуса кнопок в таблице
    if action == "status_only":
        is_active = (run_command(f"systemctl is-active {svc}") == "active")
        return jsonify({"success": True, "active": is_active})
        
    if action == "restart": run_command(f"systemctl restart {svc}")
    elif action == "start": run_command(f"systemctl start {svc}")
    elif action == "stop": run_command(f"systemctl stop {svc}")
    elif action == "delete":
        if is_system:
            return jsonify({"success": False, "error": "Удаление системных служб запрещено."})
        run_command(f"systemctl stop {svc} && systemctl disable {svc}")
        os.remove(os.path.join(SYSTEMD_DIR, svc))
        run_command("systemctl daemon-reload")
        return jsonify({"success": True})
        
    is_active = (run_command(f"systemctl is-active {svc}") == "active")
    n = 100 if action == "full_logs" else 15
    logs = run_command(f"journalctl -u {svc} -n {n} --no-pager --output=cat")
    
    return jsonify({"success": True, "active": is_active, "logs": clean_logs(logs)})

@app.route('/api/save_order', methods=['POST'])
@login_required
def update_order():
    order = request.json.get('order', [])
    save_bots_order(order)
    return jsonify({"success": True})

@app.route('/api/system_stats', methods=['GET'])
@login_required
def api_system_stats():
    global last_net_io, last_net_time
    
    # 1. Основные метрики системы
    cpu_percent = psutil.cpu_percent(interval=0.1)
    cpu_cores = psutil.cpu_count(logical=True)
    
    # Получаем Load Average (нагрузку ОС за 1, 5 и 15 минут)
    # В Windows этой функции нет, поэтому защищаем через try/except
    try:
        load1, load5, load15 = os.getloadavg()
        load_avg = f"{round(load1, 2)} / {round(load5, 2)} / {round(load15, 2)}"
    except AttributeError:
        load_avg = "N/A"
    
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disk = psutil.disk_usage('/')
    
    # Расчет скорости сети
    net_io = psutil.net_io_counters()
    current_time = time.time()
    
    upload_speed = 0
    download_speed = 0
    
    if last_net_io is not None and last_net_time > 0:
        time_diff = current_time - last_net_time
        if time_diff > 0:
            upload_speed = (net_io.bytes_sent - last_net_io.bytes_sent) / time_diff
            download_speed = (net_io.bytes_recv - last_net_io.bytes_recv) / time_diff
            
    last_net_io = net_io
    last_net_time = current_time
    
    stats = {
        "cpu": {
            "percent": cpu_percent,
            "cores": cpu_cores,
            "load_avg": load_avg
        },
        "ram": {"percent": mem.percent, "used": mem.used, "total": mem.total},
        "swap": {"percent": swap.percent, "used": swap.used, "total": swap.total},
        "disk": {"percent": disk.percent, "used": disk.used, "total": disk.total},
        "network": {
            "upload": upload_speed,
            "download": download_speed
        }
    }
    
    # 2. Список процессов
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent', 'memory_percent']):
        try:
            pinfo = proc.info
            cmdline = pinfo.get('cmdline')
            path = " ".join(cmdline) if cmdline else pinfo.get('name', '')
            processes.append({
                "pid": pinfo['pid'],
                "name": pinfo['name'],
                "path": path,
                "cpu": round(pinfo['cpu_percent'] or 0.0, 1),
                "ram": round(pinfo['memory_percent'] or 0.0, 1)
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
            
    processes.sort(key=lambda x: x['cpu'], reverse=True)
    processes = processes[:150]

    return jsonify({"success": True, "stats": stats, "processes": processes})

# ========================================
# API VPN / XRAY
# ========================================
@app.route('/vpn/add', methods=['POST'])
@login_required
def vpn_add():
    domain = request.form.get('domain', '').strip().replace('http://', '').replace('https://', '').split('/')[0]
    if domain:
        with open('/etc/xray/config.json', 'r') as f: config = json.load(f)
        for rule in config['routing']['rules']:
            if rule.get('outboundTag') == 'direct' and 'domain' in rule:
                if f"domain:{domain}" not in rule['domain'] and domain not in rule['domain']:
                    rule['domain'].append(f"domain:{domain}")
                    break
        with open('/etc/xray/config.json', 'w') as f: json.dump(config, f, indent=2)
        run_command('systemctl restart xray')
    return redirect(url_for('vpn'))

@app.route('/vpn/remove', methods=['POST'])
@login_required
def vpn_remove():
    domain = request.json.get('domain')
    if domain:
        with open('/etc/xray/config.json', 'r') as f: config = json.load(f)
        for rule in config['routing']['rules']:
            if rule.get('outboundTag') == 'direct' and 'domain' in rule:
                rule['domain'] = [d for d in rule['domain'] if domain not in d]
        with open('/etc/xray/config.json', 'w') as f: json.dump(config, f, indent=2)
        run_command('systemctl restart xray')
    return jsonify({'status': 'ok'})

# ========================================
# МАРШРУТ И API ДЛЯ СИСТЕМНЫХ ЛОГОВ
# ========================================
@app.route('/logs')
@login_required
def system_logs_page():
    return render_template('logs.html')

@app.route('/api/system_logs', methods=['POST'])
@login_required
def api_system_logs():
    filters = request.json or {}
    lines = filters.get('lines', 300) 
    priority = filters.get('priority', 'all')
    search = filters.get('search', '').lower()

    cmd = f"journalctl -r -n {lines} -o json"
    
    if priority == 'error':
        cmd += " -p 0..3"
    elif priority == 'warning':
        cmd += " -p 4"
    elif priority == 'info':
        cmd += " -p 5..7"

    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        logs = []
        for line in result.stdout.split('\n'):
            if not line.strip(): continue
            try:
                entry = json.loads(line)
                
                # Извлекаем и безопасно декодируем сообщение
                msg = entry.get('MESSAGE', '')
                if isinstance(msg, list): 
                    msg = bytes(msg).decode('utf-8', errors='replace')
                elif not isinstance(msg, str):
                    msg = str(msg)
                
                # === ИСПРАВЛЕНИЕ: Очищаем сообщение от ANSI цветовых кодов ===
                msg = clean_logs(msg)
                
                # Фильтр по тексту
                source = entry.get('SYSLOG_IDENTIFIER', entry.get('_SYSTEMD_UNIT', 'unknown'))
                if search and search not in msg.lower() and search not in source.lower():
                    continue
                    
                # Форматируем время
                timestamp = int(entry.get('__REALTIME_TIMESTAMP', 0)) // 1000000
                date_str = datetime.fromtimestamp(timestamp).strftime('%d.%m %H:%M:%S') if timestamp else ""
                
                # Определяем уровень критичности
                prio_num = int(entry.get('PRIORITY', 6))
                if prio_num <= 3: prio_str = "ERROR"
                elif prio_num == 4: prio_str = "WARNING"
                else: prio_str = "INFO"

                logs.append({
                    "time": date_str,
                    "priority": prio_str,
                    "source": source,
                    "message": msg # Теперь тут чистый текст
                })
            except:
                pass
                
        return jsonify({"success": True, "logs": logs})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

# Маршрут для страницы Пользователей
@app.route('/vpn_users')
@login_required
def vpn_users_page():
    return render_template('vpn_users.html')

def get_outline_connections():
    """Специальная функция для извлечения IP из изолированного контейнера Outline"""
    inbound = {}
    outbound = {}
    container_name = "shadowbox"
    try:
        # Ищем контейнер
        res = subprocess.run(['docker', 'ps', '--format', '{{.Names}}'], capture_output=True, text=True)
        if 'shadowbox' not in res.stdout:
            res2 = subprocess.run(['docker', 'ps', '--filter', 'ancestor=quay.io/outline/shadowbox', '--format', '{{.Names}}'], capture_output=True, text=True)
            if res2.stdout.strip():
                container_name = res2.stdout.strip().split('\n')[0]
        
        # Запускаем netstat прямо внутри контейнера
        net_res = subprocess.run(['docker', 'exec', container_name, 'netstat', '-tun'], capture_output=True, text=True)
        for line in net_res.stdout.split('\n'):
            line = line.strip()
            # Нас интересуют установленные TCP соединения и любой UDP трафик
            if 'ESTABLISHED' in line or line.startswith('udp'):
                parts = line.split()
                if len(parts) >= 5:
                    local_addr = parts[3]
                    foreign_addr = parts[4]
                    
                    if ':' not in local_addr or ':' not in foreign_addr:
                        continue
                        
                    f_ip, f_port = foreign_addr.rsplit(':', 1)
                    l_ip, l_port = local_addr.rsplit(':', 1)
                    
                    # Очищаем IP от формата IPv6
                    f_ip = f_ip.replace('::ffff:', '')
                    
                    if f_ip in ('127.0.0.1', '::1', '0.0.0.0', '*'):
                        continue
                        
                    try:
                        f_port_num = int(f_port)
                        l_port_num = int(l_port)
                        
                        # Если порт назначения стандартный (80, 443 и тд), а локальный случайный - это запрос в интернет (Исходящее)
                        # Иначе это клиент подключился к порту ключа Outline (Входящее)
                        if f_port_num < 10240 and l_port_num > 10240:
                            outbound[f_ip] = outbound.get(f_ip, 0) + 1
                        else:
                            inbound[f_ip] = inbound.get(f_ip, 0) + 1
                    except:
                        pass
    except:
        pass
        
    return inbound, outbound


def get_active_vpn_users():
    """Собирает входящие и исходящие IP для Xray, 3proxy, Danted и Outline"""
    # 1. Собираем данные с обычных прокси на сервере (Xray, 3proxy, Danted)
    proxy_names = ['xray', '3proxy', 'danted']
    proxy_pids = set()
    
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            for p_name in proxy_names:
                if p_name in proc.info['name'].lower():
                    proxy_pids.add(proc.info['pid'])
        except: pass

    inbound_ips = {}  
    outbound_ips = {} 
    
    local_ips = set()
    for interface, snics in psutil.net_if_addrs().items():
        for snic in snics:
            if snic.family == socket.AF_INET:
                local_ips.add(snic.address)

    listening_ports = set()
    for conn in psutil.net_connections(kind='inet'):
        if conn.pid in proxy_pids:
            if conn.status == 'LISTEN' or conn.type == socket.SOCK_DGRAM:
                listening_ports.add(conn.laddr.port)

    for conn in psutil.net_connections(kind='inet'):
        if conn.pid in proxy_pids and conn.raddr:
            remote_ip = conn.raddr.ip
            
            if remote_ip in local_ips or remote_ip.startswith('127.') or remote_ip.startswith('::1'):
                continue
                
            if conn.laddr.port in listening_ports:
                inbound_ips[remote_ip] = inbound_ips.get(remote_ip, 0) + 1
            else:
                outbound_ips[remote_ip] = outbound_ips.get(remote_ip, 0) + 1

    # 2. Добавляем данные из изолированного контейнера Outline
    out_inbound, out_outbound = get_outline_connections()
    
    for ip, count in out_inbound.items():
        inbound_ips[ip] = inbound_ips.get(ip, 0) + count
        
    for ip, count in out_outbound.items():
        outbound_ips[ip] = outbound_ips.get(ip, 0) + count

    return inbound_ips, outbound_ips


def analyze_proxy_logs():
    """Связывает IP с именами и определяет, кто к каким сайтам обращался (учитывает несколько юзеров на 1 IP)"""
    ip_to_users = {}      # IP -> Множество (Set) юзеров
    target_to_users = {}  # Сайт -> Множество (Set) юзеров
    
    def add_user_to_ip(ip, user):
        if user and user not in ('-', 'Unknown', 'unknown'):
            if ip not in ip_to_users:
                ip_to_users[ip] = set()
            ip_to_users[ip].add(user)

    def add_target(target, client_ip, user):
        target_ip = target.split(':')[0]
        if target_ip not in target_to_users:
            target_to_users[target_ip] = set()
            
        if user and user not in ('-', 'Unknown', 'unknown'):
            target_to_users[target_ip].add(user)
        else:
            target_to_users[target_ip].add(client_ip)

    # Анализируем 3proxy
    try:
        for c in get_3proxy_connections():
            client_ip = c['client'].split(':')[0]
            user = c['user']
            add_user_to_ip(client_ip, user)
            if c['dest'] != 'ОШИБКА':
                add_target(c['dest'], client_ip, user)
    except: pass
    
    # Анализируем Danted
    try:
        for c in get_danted_connections():
            client_ip = c['client'].split(':')[0]
            user = c['user']
            add_user_to_ip(client_ip, user)
            if c['dest'] != 'unknown' and not str(c['dest']).startswith('Local:'):
                add_target(c['dest'], client_ip, user)
    except: pass

    # Анализируем Xray
    try:
        for c in get_recent_connections():
            client_ip = c['client'].split(':')[0]
            add_target(c['dest'], client_ip, None)
    except: pass
    
    # Преобразуем IP-адреса клиентов в имена пользователей (если с одного IP сидит несколько, перечислим всех)
    final_target_to_user = {}
    for target, userset in target_to_users.items():
        final_set = set()
        for u in userset:
            if u in ip_to_users:
                for known_user in ip_to_users[u]:
                    final_set.add(known_user)
            else:
                final_set.add(u)
        final_target_to_user[target] = list(final_set)
        
    # Преобразуем словарь {IP: set("Zotic", "Ivan")} в {IP: "Zotic, Ivan"} для удобного вывода в HTML
    final_ip_to_users = {ip: ", ".join(users) for ip, users in ip_to_users.items()}
        
    return final_ip_to_users, final_target_to_user


@app.route('/api/vpn_users', methods=['GET'])
@login_required
def api_vpn_users():
    inbound, outbound = get_active_vpn_users()
    limits = get_limits()
    known_users, target_to_user = analyze_proxy_logs()
    
    # 1. ВХОДЯЩИЕ (Клиенты)
    inbound_list = []
    all_inbound_ips = set(inbound.keys()).union(set(limits.keys()))
    
    for ip in all_inbound_ips:
        inbound_list.append({
            "ip": ip,
            "username": known_users.get(ip, ""), # Теперь здесь может быть "User1, User2"
            "connections": inbound.get(ip, 0),
            "limit": limits.get(ip, {}).get('speed', None)
        })
    inbound_list.sort(key=lambda x: (x['connections'] > 0, x['connections']), reverse=True)

    # 2. ИСХОДЯЩИЕ (Сайты)
    outbound_list = []
    for ip, count in outbound.items():
        domain = reverse_dns(ip)
        
        users_list = target_to_user.get(ip, [])
        if not users_list and domain and domain in target_to_user:
            users_list = target_to_user[domain]
            
        users_str = ", ".join(users_list) if users_list else "Неизвестно"
        
        outbound_list.append({
            "ip": ip,
            "domain": domain if domain else "",
            "connections": count,
            "users": users_str
        })
    outbound_list.sort(key=lambda x: x['connections'], reverse=True)

    return jsonify({
        "success": True, 
        "inbound": inbound_list,
        "outbound": outbound_list
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=443, debug=True)