let currentSort = 'cpu'; 
let sortDesc = true;     
let processData = [];    
let isPaused = false;

// ==========================================
// УПРАВЛЕНИЕ ОБНОВЛЕНИЯМИ
// ==========================================
function togglePause() {
    isPaused = !isPaused;
    document.getElementById('pauseIcon').innerText = isPaused ? 'play_arrow' : 'pause';
    document.getElementById('pauseBtn').className = isPaused 
        ? 'btn btn-secondary shadow-sm d-flex align-items-center gap-1' 
        : 'btn btn-primary shadow-sm d-flex align-items-center gap-1';
    document.getElementById('pauseText').innerText = isPaused ? 'Пауза' : 'Автообновление';
    if (!isPaused) fetchStats(); 
}

// ==========================================
// КОНВЕРТЕРЫ ЕДИНИЦ ИЗМЕРЕНИЯ
// ==========================================
function bytesToGB(bytes) {
    return (bytes / (1024 ** 3)).toFixed(2);
}

function formatNetworkSpeed(bitsPerSec) {
    if (bitsPerSec === 0) return '0 bit/s';
    const k = 1000; 
    const sizes = ['bit/s', 'Kbit/s', 'Mbit/s', 'Gbit/s'];
    const i = Math.floor(Math.log(bitsPerSec) / Math.log(k));
    return parseFloat((bitsPerSec / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function formatDiskBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function getBarColorClass(percent) {
    if (percent < 60) return 'bg-success';
    if (percent < 85) return 'bg-warning';
    return 'bg-danger';
}

// ==========================================
// ЗАГРУЗКА И ОТРИСОВКА СТАТИСТИКИ (ДАШБОРД)
// ==========================================
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

function updateDashboard(stats) {
    document.getElementById('cpuText').innerText = stats.cpu.percent + '%';
    document.getElementById('cpuBar').style.width = stats.cpu.percent + '%';
    document.getElementById('cpuBar').className = 'progress-bar ' + getBarColorClass(stats.cpu.percent);
    document.getElementById('cpuDetails').innerText = `Ядра: ${stats.cpu.cores} | Load: ${stats.cpu.load_avg}`;

    document.getElementById('ramText').innerText = stats.ram.percent + '%';
    document.getElementById('ramDetails').innerText = `${bytesToGB(stats.ram.used)} GB / ${bytesToGB(stats.ram.total)} GB`;
    document.getElementById('ramBar').style.width = stats.ram.percent + '%';
    document.getElementById('ramBar').className = 'progress-bar ' + getBarColorClass(stats.ram.percent);

    document.getElementById('swapText').innerText = stats.swap.percent + '%';
    document.getElementById('swapDetails').innerText = `${bytesToGB(stats.swap.used)} GB / ${bytesToGB(stats.swap.total)} GB`;
    document.getElementById('swapBar').style.width = stats.swap.percent + '%';
    document.getElementById('swapBar').className = 'progress-bar ' + getBarColorClass(stats.swap.percent);

    document.getElementById('diskText').innerText = stats.disk.percent + '%';
    document.getElementById('diskDetails').innerText = `${bytesToGB(stats.disk.used)} GB / ${bytesToGB(stats.disk.total)} GB`;
    document.getElementById('diskBar').style.width = stats.disk.percent + '%';
    document.getElementById('diskBar').className = 'progress-bar ' + getBarColorClass(stats.disk.percent);

    document.getElementById('netDownload').innerText = formatNetworkSpeed(stats.network.download);
    document.getElementById('netUpload').innerText = formatNetworkSpeed(stats.network.upload);
}

// ==========================================
// СОРТИРОВКА И ОТРИСОВКА ПРОЦЕССОВ
// ==========================================
function changeSort(column) {
    if (currentSort === column) {
        sortDesc = !sortDesc; 
    } else {
        currentSort = column;
        sortDesc = true;     
    }
    
    document.getElementById('sort-pid').innerText = '';
    document.getElementById('sort-name').innerText = '';
    document.getElementById('sort-cpu').innerText = '';
    document.getElementById('sort-ram_mb').innerText = '';
    
    let arrow = sortDesc ? '▼' : '▲';
    document.getElementById('sort-' + column).innerText = arrow;
    
    renderProcessTable();
}

function renderProcessTable() {
    const tbody = document.getElementById('processList');
    const searchQuery = document.getElementById('procSearch').value.toLowerCase();
    
    let filteredData = processData.filter(p => 
        p.name.toLowerCase().includes(searchQuery) || 
        p.path.toLowerCase().includes(searchQuery) ||
        p.pid.toString().includes(searchQuery)
    );
    
    filteredData.sort((a, b) => {
        let valA = a[currentSort];
        let valB = b[currentSort];
        
        if (typeof valA === 'string') {
            return sortDesc ? valB.localeCompare(valA) : valA.localeCompare(valB);
        } else {
            return sortDesc ? valB - valA : valA - valB;
        }
    });
    
    tbody.innerHTML = '';
    if (filteredData.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-center py-4 text-muted">Процессы не найдены</td></tr>';
        return;
    }

    filteredData.forEach(p => {
        const tr = document.createElement('tr');
        
        let rowClass = (p.cpu > 50 || p.ram_percent > 30) ? 'table-warning' : '';
        tr.className = rowClass;
        
        let cpuColor = 'bg-secondary';
        if (p.cpu > 50) cpuColor = 'bg-danger';
        else if (p.cpu > 10) cpuColor = 'bg-warning text-dark';
        
        let ramColor = 'bg-light text-dark border';
        if (p.ram_percent > 50) ramColor = 'bg-danger';
        else if (p.ram_percent > 10) ramColor = 'bg-warning text-dark';
        else if (p.ram_mb > 500) ramColor = 'bg-secondary'; // Подсвечиваем серым тяжелые в МБ, но легкие в % (для многогигабайтных серверов)

        tr.innerHTML = `
            <td class="ps-4 text-muted">${p.pid}</td>
            <td class="fw-bold text-truncate">${p.name}</td>
            <td class="text-muted text-truncate" title="${p.path}">${p.path}</td>
            <td class="text-center"><span class="badge ${cpuColor}">${p.cpu}%</span></td>
            <td class="text-center pe-4"><span class="badge ${ramColor}">${p.ram_mb} MB (${p.ram_percent}%)</span></td>
        `;
        tbody.appendChild(tr);
    });
}

document.getElementById('procSearch').addEventListener('input', renderProcessTable);

// ==========================================
// АНАЛИЗАТОР ДИСКА (Кэширующий)
// ==========================================
let diskModal = null;
let wasPausedBeforeDiskModal = false;

// Объект для кэширования: { "/var": { data: [...], time: 12345678 } }
let diskCache = {}; 
let currentDiskPath = '/';

document.addEventListener("DOMContentLoaded", () => {
    diskModal = new bootstrap.Modal(document.getElementById('diskUsageModal'));

    document.getElementById('diskUsageModal').addEventListener('show.bs.modal', function () {
        wasPausedBeforeDiskModal = isPaused;
        if (!isPaused) togglePause(); 
    });

    document.getElementById('diskUsageModal').addEventListener('hidden.bs.modal', function () {
        if (!wasPausedBeforeDiskModal && isPaused) togglePause(); 
    });
});

function formatDiskBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function openDiskAnalyzer() {
    diskModal.show();
    loadDiskPath('/'); 
}

// Функция для копирования пути в буфер обмена
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        // Можно добавить всплывающее уведомление (Toast), но для скорости ограничимся консолью
        console.log("Скопировано: " + text);
    }).catch(err => {
        console.error('Ошибка копирования: ', err);
    });
}

// Вынесли рендер в отдельную функцию, чтобы использовать для кэша
function renderDiskList(path, items) {
    const list = document.getElementById('diskUsageList');
    document.getElementById('currentDiskPath').innerText = path;
    currentDiskPath = path;
    list.innerHTML = '';

    // 1. СНАЧАЛА ОТРИСОВЫВАЕМ КНОПКУ "НАЗАД" (если не в корне)
    if (path !== '/') {
        const parentPath = path.substring(0, path.lastIndexOf('/')) || '/';
        const backBtn = document.createElement('button');
        backBtn.className = 'list-group-item list-group-item-action d-flex justify-content-between align-items-center bg-light';
        backBtn.style.cursor = 'pointer';
        backBtn.onclick = () => loadDiskPath(parentPath);
        backBtn.innerHTML = `
            <div class="d-flex align-items-center gap-3 text-primary">
                <span class="material-symbols-outlined fs-4">turn_left</span>
                <span class="fw-bold">.. (Назад)</span>
            </div>
        `;
        list.appendChild(backBtn);
    }

    // 2. ОТРИСОВЫВАЕМ ПАПКИ И ФАЙЛЫ
    items.forEach(item => {
        if (item.type === 'up') return; // Игнорируем старую кнопку "назад", пришедшую с бэкенда

        const btn = document.createElement('div'); // Теперь это div, так как внутри есть кнопка копирования
        btn.className = 'list-group-item list-group-item-action d-flex justify-content-between align-items-center';
        
        let icon = 'draft';
        let iconColor = 'text-secondary';
        
        if (item.type === 'dir') {
            icon = 'folder';
            iconColor = 'text-warning';
            btn.onclick = (e) => {
                // Если кликнули не по кнопке копирования - заходим в папку
                if (!e.target.closest('.copy-btn')) {
                    loadDiskPath(item.path);
                }
            };
            btn.style.cursor = 'pointer';
        }

        let sizeBadgeClass = 'bg-light text-dark border';
        if (item.size > 1024 ** 3) sizeBadgeClass = 'bg-danger text-white'; 
        else if (item.size > 500 * 1024 ** 2) sizeBadgeClass = 'bg-warning text-dark'; 

        btn.innerHTML = `
            <div class="d-flex align-items-center gap-3 text-truncate pe-2" style="width: 70%;">
                <span class="material-symbols-outlined ${iconColor} fs-4">${icon}</span>
                <span class="text-truncate fw-bold" title="${item.name}">${item.name}</span>
            </div>
            <div class="d-flex align-items-center gap-2">
                <span class="badge ${sizeBadgeClass} fs-6 px-3 py-2 rounded-pill shadow-sm">${formatDiskBytes(item.size)}</span>
                <button class="btn btn-sm btn-outline-secondary border-0 p-1 copy-btn d-flex" onclick="copyToClipboard('${item.path}')" title="Скопировать путь">
                    <span class="material-symbols-outlined fs-5">content_copy</span>
                </button>
            </div>
        `;
        list.appendChild(btn);
    });
}

async function loadDiskPath(path) {
    const loader = document.getElementById('diskLoader');
    const list = document.getElementById('diskUsageList');

    // Проверяем кэш. Если папку сканировали менее 60 секунд назад - берем из кэша
    const now = Date.now();
    if (diskCache[path] && (now - diskCache[path].time < 60000)) {
        renderDiskList(path, diskCache[path].items);
        return;
    }

    // Если в кэше нет - загружаем
    document.getElementById('currentDiskPath').innerText = path;
    loader.style.display = 'block';
    list.innerHTML = '<div class="text-center py-5 text-muted">Идет анализ размера файлов. Это может занять несколько секунд...</div>';

    try {
        const res = await fetch('/api/disk_usage', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: path })
        });
        
        if (res.status === 401) { location.reload(); return; }
        const data = await res.json();
        
        loader.style.display = 'none';

        if (data.success) {
            // Сохраняем в кэш
            diskCache[path] = { items: data.items, time: now };
            renderDiskList(path, data.items);
        } else {
            list.innerHTML = `<div class="text-center py-4 text-danger">Ошибка: ${data.error}</div>`;
        }
    } catch (e) {
        loader.style.display = 'none';
        list.innerHTML = `<div class="text-center py-4 text-danger">Ошибка сети или сервера</div>`;
    }
}