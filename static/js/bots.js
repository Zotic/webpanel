let currentSelectedFile = null;
let currentFullLogBot = null; 
let isAutoRefresh = true;
let pollInterval = null;
let transitioningBots = new Set();

window.onload = function() {
    document.querySelectorAll('.log-box').forEach(box => { box.scrollTop = box.scrollHeight; });
    startPolling(); 
}

function toggleAutoRefresh() {
    isAutoRefresh = !isAutoRefresh;
    const btn = document.getElementById('autoRefreshBtn');
    if (isAutoRefresh) {
        btn.className = 'btn btn-success shadow-sm';
        btn.innerText = 'Автообновление: ВКЛ';
        startPolling();
    } else {
        btn.className = 'btn btn-secondary shadow-sm';
        btn.innerText = 'Автообновление: ВЫКЛ';
        clearInterval(pollInterval);
    }
}

function startPolling() {
    if (pollInterval) clearInterval(pollInterval);
    pollInterval = setInterval(async () => {
        const botCols = document.querySelectorAll('.bot-col');
        for (let col of botCols) {
            const botName = col.id.replace('bot-', '');
            if (transitioningBots.has(botName)) continue;
            try {
                const res = await fetch('/api/action', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ bot_name: botName, action: 'logs' })
                });
                if (res.status === 401) { location.reload(); return; }
                const data = await res.json();
                if (data.success && !transitioningBots.has(botName)) updateBotUI(botName, data);
            } catch (e) { console.error(e); }
        }
        if (currentFullLogBot && document.getElementById('fullLogsModal').classList.contains('show')) {
            fetchFullLogs(currentFullLogBot);
        }
    }, 5000);
}

function updateBotUI(botName, data) {
    if (data.active !== undefined) {
        let badge = document.getElementById('badge-' + botName);
        let toggleBtn = document.getElementById('toggle-btn-' + botName);
        if (data.active) {
            badge.className = 'badge bg-success'; badge.innerText = 'Активен';
            toggleBtn.className = 'action-btn btn-red';
            toggleBtn.innerHTML = '<span class="material-symbols-outlined">stop_circle</span>';
            toggleBtn.title = 'Остановить';
            toggleBtn.setAttribute('onclick', `botAction('${botName}', 'stop')`);
        } else {
            badge.className = 'badge bg-danger'; badge.innerText = 'Остановлен';
            toggleBtn.className = 'action-btn btn-green';
            toggleBtn.innerHTML = '<span class="material-symbols-outlined">play_arrow</span>'; 
            toggleBtn.title = 'Запустить';
            toggleBtn.setAttribute('onclick', `botAction('${botName}', 'start')`);
        }
    }
    if (data.logs !== undefined) {
        let logBox = document.getElementById('logs-' + botName);
        let isAtBottom = (logBox.scrollHeight - logBox.scrollTop - logBox.clientHeight) < 10;
        if (logBox.innerText !== data.logs) {
            logBox.innerText = data.logs;
            if (isAtBottom) logBox.scrollTop = logBox.scrollHeight;
        }
    }
}

async function openFullLogs(botName) {
    currentFullLogBot = botName;
    document.getElementById('fullLogsTitle').innerHTML = `<span class="material-symbols-outlined text-success">terminal</span> Логи: ${botName}`;
    document.getElementById('fullLogsContent').innerText = 'Загрузка...';
    new bootstrap.Modal(document.getElementById('fullLogsModal')).show();
    await fetchFullLogs(botName);
}

async function fetchFullLogs(botName) {
    const res = await fetch('/api/action', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ bot_name: botName, action: 'full_logs' })
    });
    if (res.status === 401) { location.reload(); return; }
    const data = await res.json();
    if (data.success) {
        let box = document.getElementById('fullLogsContent');
        let isAtBottom = (box.scrollHeight - box.scrollTop - box.clientHeight) < 10;
        if (box.innerText !== data.logs) {
            box.innerText = data.logs;
            if (isAtBottom || box.scrollTop === 0) box.scrollTop = box.scrollHeight;
        }
    }
}

function openAddBotModal() {
    document.getElementById('newBotName').value = '';
    currentSelectedFile = null;
    document.getElementById('selectedFile').innerText = 'Файл не выбран';
    loadFiles('/root/Bots'); 
    new bootstrap.Modal(document.getElementById('addBotModal')).show();
}

async function loadFiles(path) {
    const res = await fetch('/api/files', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: path })
    });
    if (res.status === 401) { location.reload(); return; } 
    const data = await res.json();
    
    document.getElementById('currentPath').innerText = data.path;
    const browser = document.getElementById('fileBrowser');
    browser.innerHTML = '';

    data.items.forEach(item => {
        const el = document.createElement('button');
        el.className = 'list-group-item list-group-item-action cursor-pointer d-flex align-items-center py-3';
        if (item.type === 'dir') {
            el.innerHTML = '<span class="material-symbols-outlined text-warning me-3">folder</span> <span class="fw-bold">' + item.name + '</span>';
            el.onclick = () => loadFiles(item.path);
        } else {
            el.innerHTML = '<span class="material-symbols-outlined text-primary me-3">code</span> ' + item.name;
            el.onclick = () => {
                document.querySelectorAll('#fileBrowser button').forEach(b => {
                    b.classList.remove('active', 'bg-primary', 'text-white');
                });
                el.classList.add('active', 'bg-primary', 'text-white');
                currentSelectedFile = item.path;
                document.getElementById('selectedFile').innerText = 'Выбран: ' + item.name;
            };
        }
        browser.appendChild(el);
    });
}

async function submitBot() {
    const botName = document.getElementById('newBotName').value.trim();
    if (!botName) { alert('Введите название бота!'); return; }
    if (botName.includes(' ')) { alert('Имя не должно содержать пробелы!'); return; }
    if (!currentSelectedFile) { alert('Выберите .py файл!'); return; }

    const res = await fetch('/api/add_bot', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ bot_name: botName, file_path: currentSelectedFile })
    });
    if (res.status === 401) { location.reload(); return; }
    const data = await res.json();
    if (data.success) { location.reload(); } else { alert('Ошибка: ' + data.error); }
}

async function botAction(botName, action) {
    if (action === 'delete' && !confirm('Точно удалить бота ' + botName + '?')) return;
    let badge = document.getElementById('badge-' + botName);
    let interval = null;

    if (action === 'stop' || action === 'restart') {
        transitioningBots.add(botName); 
        let countdown = 5;
        badge.className = 'badge bg-warning text-dark';
        badge.innerText = `${action === 'stop' ? 'Остановка' : 'Рестарт'} (${countdown})...`;
        
        interval = setInterval(() => {
            countdown--;
            if (countdown > 0) badge.innerText = `${action === 'stop' ? 'Остановка' : 'Рестарт'} (${countdown})...`;
            else { badge.innerText = `Принудительно...`; clearInterval(interval); }
        }, 1000);
    } else if (action === 'start') {
        transitioningBots.add(botName);
        badge.className = 'badge bg-warning text-dark'; badge.innerText = `Запуск...`;
    }

    try {
        const res = await fetch('/api/action', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ bot_name: botName, action: action })
        });
        if (res.status === 401) { location.reload(); return; }
        const data = await res.json();
        
        if (interval) clearInterval(interval);
        transitioningBots.delete(botName);

        if (data.success) {
            if (action === 'delete') document.getElementById('bot-' + botName).remove();
            else updateBotUI(botName, data); 
        } else alert('Ошибка: ' + data.error);
    } catch (e) {
        if (interval) clearInterval(interval);
        transitioningBots.delete(botName); console.error(e);
    }
}

// ==========================================
// Инициализация Drag & Drop сортировки
// ==========================================
document.addEventListener('DOMContentLoaded', function() {
    let container = document.getElementById('botsContainer');
    if (container) {
        Sortable.create(container, {
            handle: '.drag-handle', // Хватать можно только за специальную иконку
            animation: 150,         // Плавная анимация перемещения
            ghostClass: 'bg-light', // Подсветка "призрака" (пустого места)
            onEnd: function (evt) {
                // Как только пользователь отпустил карточку, собираем новый порядок
                let newOrder = [];
                document.querySelectorAll('.bot-col').forEach(col => {
                    newOrder.push(col.id.replace('bot-', ''));
                });
                
                // Отправляем новый порядок на сервер (сохранится в JSON)
                fetch('/api/save_order', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({order: newOrder})
                }).catch(err => console.error("Ошибка сохранения порядка:", err));
            }
        });
    }
});