let currentSort = 'cpu'; // По умолчанию сортируем по CPU
let sortDesc = true;     // По убыванию
let processData = [];    // Хранилище процессов для локальной сортировки и поиска

// Конвертер байтов в гигабайты
function bytesToGB(bytes) {
    return (bytes / (1024 ** 3)).toFixed(2);
}

// Изменение цвета прогресс-бара в зависимости от нагрузки
function getBarColorClass(percent) {
    if (percent < 60) return 'bg-success';
    if (percent < 85) return 'bg-warning';
    return 'bg-danger';
}

// Запрос данных с сервера
async function fetchStats() {
    try {
        const res = await fetch('/api/system_stats');
        if (res.status === 401) { location.reload(); return; }
        const data = await res.json();
        
        if (data.success) {
            updateDashboard(data.stats);
            processData = data.processes;
            renderProcessTable();
        }
    } catch (e) {
        console.error("Ошибка загрузки статистики:", e);
    }
}

// Обновление верхних карточек (CPU, RAM, Swap, Disk)
function updateDashboard(stats) {
    // CPU
    document.getElementById('cpuText').innerText = stats.cpu + '%';
    document.getElementById('cpuBar').style.width = stats.cpu + '%';
    document.getElementById('cpuBar').className = 'progress-bar ' + getBarColorClass(stats.cpu);

    // RAM
    document.getElementById('ramText').innerText = stats.ram.percent + '%';
    document.getElementById('ramDetails').innerText = `${bytesToGB(stats.ram.used)} GB / ${bytesToGB(stats.ram.total)} GB`;
    document.getElementById('ramBar').style.width = stats.ram.percent + '%';
    document.getElementById('ramBar').className = 'progress-bar ' + getBarColorClass(stats.ram.percent);

    // SWAP
    document.getElementById('swapText').innerText = stats.swap.percent + '%';
    document.getElementById('swapDetails').innerText = `${bytesToGB(stats.swap.used)} GB / ${bytesToGB(stats.swap.total)} GB`;
    document.getElementById('swapBar').style.width = stats.swap.percent + '%';
    document.getElementById('swapBar').className = 'progress-bar ' + getBarColorClass(stats.swap.percent);

    // DISK
    document.getElementById('diskText').innerText = stats.disk.percent + '%';
    document.getElementById('diskDetails').innerText = `${bytesToGB(stats.disk.used)} GB / ${bytesToGB(stats.disk.total)} GB`;
    document.getElementById('diskBar').style.width = stats.disk.percent + '%';
    document.getElementById('diskBar').className = 'progress-bar ' + getBarColorClass(stats.disk.percent);
}

// Обработчик клика по заголовку таблицы
function changeSort(column) {
    if (currentSort === column) {
        sortDesc = !sortDesc; // Меняем направление сортировки
    } else {
        currentSort = column;
        sortDesc = true;      // По умолчанию по убыванию
    }
    
    // Обновляем стрелочки в заголовках
    document.getElementById('sort-name').innerText = '';
    document.getElementById('sort-cpu').innerText = '';
    document.getElementById('sort-ram').innerText = '';
    
    let arrow = sortDesc ? '▼' : '▲';
    document.getElementById('sort-' + column).innerText = arrow;
    
    renderProcessTable();
}

// Отрисовка таблицы процессов (с учетом сортировки и поиска)
function renderProcessTable() {
    const tbody = document.getElementById('processList');
    const searchQuery = document.getElementById('procSearch').value.toLowerCase();
    
    // 1. Фильтрация
    let filteredData = processData.filter(p => 
        p.name.toLowerCase().includes(searchQuery) || 
        p.path.toLowerCase().includes(searchQuery)
    );
    
    // 2. Сортировка
    filteredData.sort((a, b) => {
        let valA = a[currentSort];
        let valB = b[currentSort];
        
        if (typeof valA === 'string') {
            return sortDesc ? valB.localeCompare(valA) : valA.localeCompare(valB);
        } else {
            return sortDesc ? valB - valA : valA - valB;
        }
    });
    
    // 3. Рендер
    tbody.innerHTML = '';
    if (filteredData.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-center py-4 text-muted">Процессы не найдены</td></tr>';
        return;
    }

    filteredData.forEach(p => {
        const tr = document.createElement('tr');
        
        // Подсвечиваем тяжелые процессы (красный, если CPU > 50% или RAM > 30%)
        let rowClass = (p.cpu > 50 || p.ram > 30) ? 'table-warning' : '';
        tr.className = rowClass;
        
        tr.innerHTML = `
            <td class="ps-4 text-muted">${p.pid}</td>
            <td class="fw-bold">${p.name}</td>
            <td style="max-width: 300px;" class="text-truncate text-muted" title="${p.path}">${p.path}</td>
            <td class="text-center"><span class="badge ${p.cpu > 10 ? 'bg-danger' : 'bg-secondary'}">${p.cpu}%</span></td>
            <td class="text-center pe-4"><span class="badge ${p.ram > 10 ? 'bg-warning text-dark' : 'bg-secondary'}">${p.ram}%</span></td>
        `;
        tbody.appendChild(tr);
    });
}

// Обработчик строки поиска
document.getElementById('procSearch').addEventListener('input', renderProcessTable);

// Запуск цикла обновления
let isPaused = false;

function togglePause() {
    isPaused = !isPaused;
    document.getElementById('pauseIcon').innerText = isPaused ? 'play_arrow' : 'pause';
    document.getElementById('pauseBtn').className = isPaused ? 'btn btn-secondary shadow-sm d-flex align-items-center gap-1' : 'btn btn-primary shadow-sm d-flex align-items-center gap-1';
    document.getElementById('pauseText').innerText = isPaused ? 'Пауза' : 'Автообновление';
    if (!isPaused) fetchStats(); // Сразу обновляем при снятии с паузы
}

// Запуск цикла обновления с учетом паузы
document.addEventListener('DOMContentLoaded', () => {
    fetchStats();
    setInterval(() => {
        if (!isPaused) fetchStats();
    }, 3000); 
});