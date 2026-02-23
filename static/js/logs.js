let isAutoRefresh = false;
let pollInterval = null;
let searchTimeout = null;

// Функция загрузки логов с сервера
async function fetchLogs() {
    const priority = document.getElementById('logPriority').value;
    const search = document.getElementById('logSearch').value;
    const tbody = document.getElementById('logsTableBody');

    try {
        const res = await fetch('/api/system_logs', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ priority: priority, search: search, lines: 300 })
        });
        
        if (res.status === 401) { location.reload(); return; }
        const data = await res.json();
        
        if (data.success) {
            tbody.innerHTML = '';
            
            if (data.logs.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" class="text-center py-5 text-muted">По вашему запросу логов не найдено.</td></tr>';
                return;
            }

            data.logs.forEach(log => {
                const tr = document.createElement('tr');
                
                // Настраиваем цвета в зависимости от уровня
                let badgeClass = 'bg-secondary';
                let rowClass = '';
                
                if (log.priority === 'ERROR') {
                    badgeClass = 'bg-danger';
                    rowClass = 'table-danger'; // Подсвечиваем всю строку слегка красным
                } else if (log.priority === 'WARNING') {
                    badgeClass = 'bg-warning text-dark';
                    rowClass = 'table-warning';
                } else if (log.priority === 'INFO') {
                    badgeClass = 'bg-primary';
                }

                tr.className = rowClass;
                tr.innerHTML = `
                    <td class="ps-3 text-muted text-nowrap">${log.time}</td>
                    <td><span class="badge ${badgeClass} w-100">${log.priority}</span></td>
                    <td class="fw-bold text-truncate" style="max-width: 180px;" title="${log.source}">${log.source}</td>
                    <td class="pe-3" style="word-break: break-word;">${log.message}</td>
                `;
                tbody.appendChild(tr);
            });
        }
    } catch (e) {
        console.error("Ошибка загрузки логов:", e);
    }
}

// Автообновление
function toggleAutoRefresh() {
    isAutoRefresh = !isAutoRefresh;
    const btn = document.getElementById('autoRefreshBtn');
    if (isAutoRefresh) {
        btn.className = 'btn btn-success shadow-sm';
        btn.innerText = 'Авто: ВКЛ';
        fetchLogs(); // Загружаем сразу
        pollInterval = setInterval(fetchLogs, 4000); // Каждые 4 секунды
    } else {
        btn.className = 'btn btn-secondary shadow-sm';
        btn.innerText = 'Авто: ВЫКЛ';
        clearInterval(pollInterval);
    }
}

// Поиск с задержкой (Debounce) - ждет пока пользователь закончит печатать
document.getElementById('logSearch').addEventListener('input', () => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {
        fetchLogs();
    }, 500); // Ждем полсекунды после последнего нажатия клавиши
});

// Загружаем логи при открытии страницы
document.addEventListener('DOMContentLoaded', fetchLogs);