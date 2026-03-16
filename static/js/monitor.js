let currentSort = 'cpu'; 
let sortDesc = true;     
let processData = [];    
let isPaused = false;
let diskModal = null;
let wasPausedBeforeDiskModal = false;
let diskCache = {}; 
let currentDiskPath = '/';

// ==========================================
// УПРАВЛЕНИЕ ОБНОВЛЕНИЯМИ
// ==========================================
function togglePause() {
    isPaused = !isPaused;
    let pauseIcon = document.getElementById('pauseIcon');
    let pauseBtn = document.getElementById('pauseBtn');
    let pauseText = document.getElementById('pauseText');
    
    if (pauseIcon) pauseIcon.innerText = isPaused ? 'play_arrow' : 'pause';
    if (pauseBtn) pauseBtn.className = isPaused 
        ? 'btn btn-secondary shadow-sm d-flex align-items-center gap-1' 
        : 'btn btn-primary shadow-sm d-flex align-items-center gap-1';
    if (pauseText) pauseText.innerText = isPaused ? 'Пауза' : 'Автообновление';
    
    if (!isPaused) fetchStats(); 
}

// ==========================================
// КОНВЕРТЕРЫ ЕДИНИЦ ИЗМЕРЕНИЯ
// ==========================================
function bytesToGB(bytes) {
    if (!bytes) return "0.00";
    return (bytes / (1024 ** 3)).toFixed(2);
}

function formatNetworkSpeed(bitsPerSec) {
    if (!bitsPerSec || bitsPerSec === 0) return '0 bit/s';
    const k = 1000; 
    const sizes = ['bit/s', 'Kbit/s', 'Mbit/s', 'Gbit/s'];
    const i = Math.floor(Math.log(bitsPerSec) / Math.log(k));
    return parseFloat((bitsPerSec / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function formatDiskBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
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
    if (isPaused) return; // Двойная защита от запросов в паузе
    
    try {
        const res = await fetch('/api/system_stats');
        if (res.status === 401) { location.reload(); return; }
        const data = await res.json();
        
        if (data && data.success) {
            updateDashboard(data.stats);
            if (data.processes) {
                processData = data.processes;
                renderProcessTable();
            }
        }
    } catch (e) {
        console.error("Ошибка загрузки статистики:", e);
    }
}

function setElementText(id, text) {
    let el = document.getElementById(id);
    if (el) el.innerText = text;
}

function setProgressBar(id, percent) {
    let el = document.getElementById(id);
    if (el) {
        el.style.width = percent + '%';
        el.className = 'progress-bar ' + getBarColorClass(percent);
    }
}

function updateDashboard(stats) {
    if (!stats) return;

    // CPU
    if (stats.cpu) {
        setElementText('cpuText', stats.cpu.percent + '%');
        setProgressBar('cpuBar', stats.cpu.percent);
        setElementText('cpuDetails', `Ядра: ${stats.cpu.cores || 0} | Load: ${stats.cpu.load_avg || '0'}`);
    }

    // RAM
    if (stats.ram) {
        setElementText('ramText', stats.ram.percent + '%');
        setElementText('ramDetails', `${bytesToGB(stats.ram.used)} GB / ${bytesToGB(stats.ram.total)} GB`);
        setProgressBar('ramBar', stats.ram.percent);
    }

    // SWAP
    if (stats.swap) {
        setElementText('swapText', stats.swap.percent + '%');
        setElementText('swapDetails', `${bytesToGB(stats.swap.used)} GB / ${bytesToGB(stats.swap.total)} GB`);
        setProgressBar('swapBar', stats.swap.percent);
    }

    // DISK
    if (stats.disk) {
        setElementText('diskText', stats.disk.percent + '%');
        setElementText('diskDetails', `${bytesToGB(stats.disk.used)} GB / ${bytesToGB(stats.disk.total)} GB`);
        setProgressBar('diskBar', stats.disk.percent);
    }

    // СЕТЬ
    if (stats.network) {
        setElementText('netDownload', formatNetworkSpeed(stats.network.download));
        setElementText('netUpload', formatNetworkSpeed(stats.network.upload));
    }
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
    
    setElementText('sort-pid', '');
    setElementText('sort-name', '');
    setElementText('sort-cpu', '');
    setElementText('sort-ram_mb', '');
    
    let arrow = sortDesc ? '▼' : '▲';
    setElementText('sort-' + column, arrow);
    
    renderProcessTable();
}

function renderProcessTable() {
    const tbody = document.getElementById('processList');
    if (!tbody) return;

    let searchInput = document.getElementById('procSearch');
    let searchQuery = searchInput ? searchInput.value.toLowerCase() : '';
    
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
        else if (p.ram_mb > 500) ramColor = 'bg-secondary text-white border-0'; 

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

// ==========================================
// АНАЛИЗАТОР ДИСКА
// ==========================================
function copyToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).catch(err => console.error(err));
    }
}

function openDiskAnalyzer() {
    // Безопасная инициализация модального окна (только по клику)
    if (!diskModal) {
        let el = document.getElementById('diskUsageModal');
        if (el) {
            diskModal = new bootstrap.Modal(el);
            
            // Навешиваем слушатели событий
            el.addEventListener('show.bs.modal', function () {
                wasPausedBeforeDiskModal = isPaused;
                if (!isPaused) togglePause(); 
            });

            el.addEventListener('hidden.bs.modal', function () {
                if (!wasPausedBeforeDiskModal && isPaused) togglePause(); 
            });
        }
    }
    
    if (diskModal) {
        diskModal.show();
        loadDiskPath('/'); 
    }
}

function renderDiskList(path, items) {
    const list = document.getElementById('diskUsageList');
    if (!list) return;

    setElementText('currentDiskPath', path);
    currentDiskPath = path;
    list.innerHTML = '';

    if (path !== '/') {
        const parentPath = path.substring(0, path.lastIndexOf('/')) || '/';
        const backBtn = document.createElement('div');
        backBtn.className = 'list-group-item list-group-item-action d-flex justify-content-between align-items-center bg-light';
        backBtn.style.cursor = 'pointer';
        backBtn.onclick = () => loadDiskPath(parentPath);
        backBtn.innerHTML = `
            <div class="d-flex align-items-center gap-3 text-primary w-100 py-2">
                <span class="material-symbols-outlined fs-4">turn_left</span>
                <span class="fw-bold">.. (Назад)</span>
            </div>
        `;
        list.appendChild(backBtn);
    }

    items.forEach(item => {
        if (item.type === 'up') return; 

        const btn = document.createElement('div'); 
        btn.className = 'list-group-item list-group-item-action d-flex justify-content-between align-items-center p-2';
        
        let icon = 'description';
        let iconColor = 'text-secondary';
        
        if (item.type === 'dir') {
            icon = 'folder';
            iconColor = 'text-warning';
            btn.onclick = (e) => {
                if (!e.target.closest('.copy-btn')) {
                    loadDiskPath(item.path); // Проваливаемся в папку
                }
            };
            btn.style.cursor = 'pointer';
        } else {
            icon = 'draft';
            iconColor = 'text-info';
            btn.onclick = (e) => {
                if (!e.target.closest('.copy-btn')) {
                    viewFileContent(item.path); // Открываем файл
                }
            };
            btn.style.cursor = 'pointer';
        }

        let sizeBadgeClass = 'bg-light text-dark border';
        if (item.size > 1024 ** 3) sizeBadgeClass = 'bg-danger text-white border-0'; 
        else if (item.size > 500 * 1024 ** 2) sizeBadgeClass = 'bg-warning text-dark border-0'; 

        btn.innerHTML = `
            <div class="d-flex align-items-center gap-3 text-truncate pe-2" style="width: 65%;">
                <span class="material-symbols-outlined ${iconColor} fs-4">${icon}</span>
                <span class="text-truncate fw-bold" style="font-size: 0.95rem;">${item.name}</span>
            </div>
            <div class="d-flex align-items-center gap-1 justify-content-end" style="width: 35%;">
                <span class="badge ${sizeBadgeClass} px-2 py-1 rounded-pill shadow-sm" style="font-size: 0.75rem;">${formatDiskBytes(item.size)}</span>
                <button class="btn btn-sm btn-outline-secondary border-0 p-1 copy-btn d-flex align-items-center justify-content-center" onclick="copyToClipboard('${item.path}')">
                    <span class="material-symbols-outlined" style="font-size: 18px;">content_copy</span>
                </button>
            </div>
        `;
        list.appendChild(btn);
    });
}

async function loadDiskPath(path) {
    let loader = document.getElementById('diskLoader');
    let list = document.getElementById('diskUsageList');
    if (!list) return;

    const now = Date.now();
    if (diskCache[path] && (now - diskCache[path].time < 60000)) {
        renderDiskList(path, diskCache[path].items);
        return;
    }

    setElementText('currentDiskPath', path);
    if (loader) loader.style.display = 'block';
    list.innerHTML = '<div class="text-center py-5 text-muted"><div class="spinner-border text-primary mb-3" role="status"></div><br>Анализ файлов (может занять время)...</div>';

    try {
        const res = await fetch('/api/disk_usage', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: path })
        });
        
        if (res.status === 401) { location.reload(); return; }
        const data = await res.json();
        
        if (loader) loader.style.display = 'none';

        if (data && data.success) {
            diskCache[path] = { items: data.items, time: now };
            renderDiskList(path, data.items);
        } else {
            list.innerHTML = `<div class="text-center py-4 text-danger">Ошибка: ${data ? data.error : 'Неизвестная ошибка'}</div>`;
        }
    } catch (e) {
        if (loader) loader.style.display = 'none';
        list.innerHTML = `<div class="text-center py-4 text-danger">Ошибка сети или сервера</div>`;
    }
}

// ==========================================
// ИНИЦИАЛИЗАЦИЯ (БЕЗОПАСНАЯ)
// ==========================================
document.addEventListener('DOMContentLoaded', () => {
    // Безопасно навешиваем поиск
    let searchEl = document.getElementById('procSearch');
    if (searchEl) {
        searchEl.addEventListener('input', renderProcessTable);
    }

    // Запускаем цикл опроса сервера
    fetchStats();
    setInterval(() => {
        if (!isPaused) fetchStats();
    }, 3000); 
});

let fileViewerModal = null;

document.addEventListener('DOMContentLoaded', () => {
    // Инициализируем модалку
    let fvEl = document.getElementById('fileViewerModal');
    if (fvEl) fileViewerModal = new bootstrap.Modal(fvEl);
});

async function viewFileContent(filePath) {
    if (!fileViewerModal) return;
    
    document.getElementById('fileViewerTitle').innerText = filePath;
    document.getElementById('fileViewerContent').value = "Чтение файла...";
    
    // Показываем окно
    fileViewerModal.show();

    try {
        const res = await fetch('/api/read_file', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: filePath })
        });
        
        if (res.status === 401) { location.reload(); return; }
        const data = await res.json();

        if (data.success) {
            document.getElementById('fileViewerContent').value = data.content;
        } else {
            document.getElementById('fileViewerContent').value = "Ошибка: " + data.error;
        }
    } catch (e) {
        document.getElementById('fileViewerContent').value = "Ошибка сети при обращении к серверу.";
    }
}