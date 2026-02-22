let currentFullLogBot = null; 
let isAutoRefresh = false; 
let pollInterval = null;
let transitioningBots = new Set();

// Фильтрация (поиск) по названию
function filterServices() {
    let input = document.getElementById('searchInput').value.toLowerCase();
    let cards = document.querySelectorAll('.bot-col');
    
    cards.forEach(card => {
        let title = card.querySelector('.text-truncate').innerText.toLowerCase();
        if (title.includes(input)) {
            card.style.display = '';
        } else {
            card.style.display = 'none';
        }
    });
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
            // Не опрашиваем сервисы, которые скрыты поиском, чтобы не грузить сервер
            if (col.style.display === 'none') continue;
            
            const botName = col.id.replace('bot-', '');
            if (transitioningBots.has(botName)) continue;
            
            try {
                const res = await fetch('/api/action', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ bot_name: botName, action: 'logs', is_system: true }) 
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
        body: JSON.stringify({ bot_name: botName, action: 'full_logs', is_system: true })
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

async function botAction(botName, action) {
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
            body: JSON.stringify({ bot_name: botName, action: action, is_system: true })
        });
        if (res.status === 401) { location.reload(); return; }
        const data = await res.json();
        
        if (interval) clearInterval(interval);
        transitioningBots.delete(botName);

        if (data.success) {
            updateBotUI(botName, data); 
        } else {
            alert('Ошибка: ' + data.error);
            botAction(botName, 'logs');
        }
    } catch (e) {
        if (interval) clearInterval(interval);
        transitioningBots.delete(botName); console.error(e);
    }
}