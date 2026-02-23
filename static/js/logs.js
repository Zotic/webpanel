let isAutoRefresh = false;
let pollInterval = null;
let searchTimeout = null;

let allLoadedLogs = [];       // Хранит все загруженные с сервера логи
let selectedSources = new Set(); // Хранит выбранные галочками источники

// Функция загрузки логов с сервера
async function fetchLogs() {
    const priority = document.getElementById('logPriority').value;
    const search = document.getElementById('logSearch').value;
    const lines = document.getElementById('logLines').value; // Читаем выбор количества строк
    const tbody = document.getElementById('logsTableBody');

    try {
        const res = await fetch('/api/system_logs', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ priority: priority, search: search, lines: parseInt(lines) })
        });
        
        if (res.status === 401) { location.reload(); return; }
        const data = await res.json();
        
        if (data.success) {
            allLoadedLogs = data.logs;
            updateSourceFilters(); // Обновляем список галочек
            renderLogs();          // Отрисовываем таблицу
        }
    } catch (e) {
        console.error("Ошибка загрузки логов:", e);
    }
}

// Построение выпадающего списка источников (галочки)
function updateSourceFilters() {
    const sourceMenu = document.getElementById('sourceFilterMenu');
    
    // Собираем все уникальные источники из загруженных логов
    const uniqueSources = new Set();
    allLoadedLogs.forEach(log => uniqueSources.add(log.source));
    const sortedSources = Array.from(uniqueSources).sort();
    
    // Если это первая загрузка, ставим галочки на все источники
    if (selectedSources.size === 0 && sortedSources.length > 0) {
        sortedSources.forEach(s => selectedSources.add(s));
    }

    sourceMenu.innerHTML = '';
    
    // Добавляем кнопки "Выбрать все / Снять все"
    const topActions = document.createElement('div');
    topActions.className = 'd-flex justify-content-between mb-2 pb-2 border-bottom';
    topActions.innerHTML = `
        <button type="button" class="btn btn-sm btn-link text-decoration-none p-0" onclick="selectAllSources(true)">Выбрать все</button>
        <button type="button" class="btn btn-sm btn-link text-decoration-none p-0 text-danger" onclick="selectAllSources(false)">Снять все</button>
    `;
    sourceMenu.appendChild(topActions);

    // Добавляем чекбоксы
    sortedSources.forEach(source => {
        const li = document.createElement('li');
        li.className = 'form-check ms-2 me-2 mb-1';
        
        const isChecked = selectedSources.has(source) ? 'checked' : '';
        
        li.innerHTML = `
            <input class="form-check-input" type="checkbox" value="${source}" id="chk_${source}" ${isChecked} onchange="toggleSource('${source}', this.checked)">
            <label class="form-check-label text-truncate w-100 cursor-pointer" for="chk_${source}" title="${source}">
                ${source}
            </label>
        `;
        sourceMenu.appendChild(li);
    });
}

// Обработка включения/выключения одной галочки
function toggleSource(source, isChecked) {
    if (isChecked) selectedSources.add(source);
    else selectedSources.delete(source);
    renderLogs(); // Перерисовываем мгновенно (без запроса к серверу)
}

// Обработка кнопок "Выбрать все / Снять все"
function selectAllSources(checkAll) {
    const checkboxes = document.querySelectorAll('#sourceFilterMenu .form-check-input');
    checkboxes.forEach(chk => {
        chk.checked = checkAll;
        if (checkAll) selectedSources.add(chk.value);
        else selectedSources.delete(chk.value);
    });
    renderLogs();
}

// Отрисовка логов в таблице
function renderLogs() {
    const tbody = document.getElementById('logsTableBody');
    tbody.innerHTML = '';

    // Фильтруем логи на основе выбранных галочек
    const filteredLogs = allLoadedLogs.filter(log => selectedSources.has(log.source));

    if (filteredLogs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="text-center py-5 text-muted">По выбранным источникам логов нет.</td></tr>';
        return;
    }

    filteredLogs.forEach(log => {
        const tr = document.createElement('tr');
        
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
        
        // Используем читаемые шрифты: Roboto для служебной информации, Consolas для самого лога
        tr.innerHTML = `
            <td class="ps-3 text-muted text-nowrap" style="font-family: 'Roboto', sans-serif; font-size: 0.8rem;">${log.time}</td>
            <td><span class="badge ${badgeClass} w-100">${log.priority}</span></td>
            <td class="fw-bold text-truncate" style="max-width: 180px; font-family: 'Roboto', sans-serif;" title="${log.source}">${log.source}</td>
            <td class="pe-3" style="font-family: Consolas, Monaco, 'Liberation Mono', monospace; font-size: 0.85rem; word-break: break-word;">${log.message}</td>
        `;
        tbody.appendChild(tr);
    });
}

// Автообновление
function toggleAutoRefresh() {
    isAutoRefresh = !isAutoRefresh;
    const btn = document.getElementById('autoRefreshBtn');
    if (isAutoRefresh) {
        btn.className = 'btn btn-success shadow-sm';
        btn.innerText = 'Авто: ВКЛ';
        fetchLogs(); 
        pollInterval = setInterval(fetchLogs, 4000); 
    } else {
        btn.className = 'btn btn-secondary shadow-sm';
        btn.innerText = 'Авто: ВЫКЛ';
        clearInterval(pollInterval);
    }
}

// Поиск с задержкой
document.getElementById('logSearch').addEventListener('input', () => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {
        fetchLogs();
    }, 500); 
});

document.addEventListener('DOMContentLoaded', fetchLogs);