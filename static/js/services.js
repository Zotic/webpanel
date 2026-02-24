let currentFullLogBot = null; 
let isAutoRefresh = false; 
let pollInterval = null;
let transitioningBots = new Set();
let logsModal = null;

document.addEventListener("DOMContentLoaded", () => {
    logsModal = new bootstrap.Modal(document.getElementById('fullLogsModal'));
});

// Быстрый поиск по таблице
function filterServices() {
    let input = document.getElementById('searchInput').value.toLowerCase();
    let rows = document.querySelectorAll('.svc-row');
    
    rows.forEach(row => {
        let title = row.querySelector('.svc-name').innerText.toLowerCase();
        row.style.display = title.includes(input) ? '' : 'none';
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

// Фоновое обновление только ВИДИМЫХ сервисов (экономия ресурсов)
function startPolling() {
    if (pollInterval) clearInterval(pollInterval);
    pollInterval = setInterval(async () => {
        const rows = document.querySelectorAll('.svc-row');
        for (let row of rows) {
            if (row.style.display === 'none') continue;
            
            const botName = row.id.replace('row-', '');
            if (transitioningBots.has(botName)) continue;
            
            try {
                const res = await fetch('/api/action', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ bot_name: botName, action: 'status_only', is_system: true }) 
                });
                if (res.status === 401) { location.reload(); return; }
                const data = await res.json();
                if (data.success && !transitioningBots.has(botName)) updateUI(botName, data);
            } catch (e) { }
        }
    }, 5000);
}

// Обновление кнопок в таблице
function updateUI(botName, data) {
    if (data.active !== undefined) {
        let badge = document.getElementById('badge-' + botName);
        let toggleBtn = document.getElementById('toggle-btn-' + botName);
        
        if (data.active) {
            badge.className = 'badge bg-success w-100'; badge.innerText = 'АКТИВЕН';
            toggleBtn.className = 'btn btn-sm btn-outline-danger d-flex align-items-center justify-content-center p-1';
            toggleBtn.innerHTML = '<span class="material-symbols-outlined fs-6">stop_circle</span>'; 
            toggleBtn.title = 'Остановить';
            toggleBtn.setAttribute('onclick', `botAction('${botName}', 'stop')`);
        } else {
            badge.className = 'badge bg-danger w-100'; badge.innerText = 'ОСТАНОВЛЕН';
            toggleBtn.className = 'btn btn-sm btn-outline-success d-flex align-items-center justify-content-center p-1';
            toggleBtn.innerHTML = '<span class="material-symbols-outlined fs-6">play_arrow</span>'; 
            toggleBtn.title = 'Запустить';
            toggleBtn.setAttribute('onclick', `botAction('${botName}', 'start')`);
        }
    }
}

// Управление сервисами (Старт/Стоп/Логи)
async function botAction(botName, action) {
    let badge = document.getElementById('badge-' + botName);
    let interval = null;

    if (action === 'logs') {
        currentFullLogBot = botName;
        document.getElementById('fullLogsTitle').innerHTML = `<span class="material-symbols-outlined text-success">terminal</span> Логи: ${botName}`;
        let box = document.getElementById('fullLogsContent');
        box.innerText = 'Загрузка...';
        logsModal.show();
        action = 'full_logs'; // Просим бэкенд отдать большие логи
    } else {
        transitioningBots.add(botName); 
        let countdown = 5;
        badge.className = 'badge bg-warning text-dark w-100';
        badge.innerText = `ЖДИТЕ (${countdown})`;
        interval = setInterval(() => {
            countdown--;
            if (countdown > 0) badge.innerText = `ЖДИТЕ (${countdown})`;
            else clearInterval(interval);
        }, 1000);
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
            if (action === 'full_logs') {
                let box = document.getElementById('fullLogsContent');
                box.innerText = data.logs || "Логов нет.";
                box.scrollTop = box.scrollHeight;
            } else {
                updateUI(botName, data); 
            }
        } else {
            if (action !== 'full_logs') alert('Ошибка: ' + data.error);
        }
    } catch (e) {
        if (interval) clearInterval(interval);
        transitioningBots.delete(botName);
    }
}