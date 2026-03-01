let currentSort = 'cpu'; 
let sortDesc = true;     
let processData = [];    
let isPaused = false;

function togglePause() {
    isPaused = !isPaused;
    document.getElementById('pauseIcon').innerText = isPaused ? 'play_arrow' : 'pause';
    document.getElementById('pauseBtn').className = isPaused 
        ? 'btn btn-secondary shadow-sm d-flex align-items-center gap-1' 
        : 'btn btn-primary shadow-sm d-flex align-items-center gap-1';
    document.getElementById('pauseText').innerText = isPaused ? 'Пауза' : 'Автообновление';
    if (!isPaused) fetchStats(); 
}

function bytesToGB(bytes) {
    return (bytes / (1024 ** 3)).toFixed(2);
}

// Новая функция для БИТОВ в секунду
function formatNetworkSpeed(bitsPerSec) {
    if (bitsPerSec === 0) return '0 bit/s';
    const k = 1000; // Сетевая скорость считается в десятичных приставках (1000)
    const sizes = ['bit/s', 'Kbit/s', 'Mbit/s', 'Gbit/s'];
    const i = Math.floor(Math.log(bitsPerSec) / Math.log(k));
    return parseFloat((bitsPerSec / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function getBarColorClass(percent) {
    if (percent < 60) return 'bg-success';
    if (percent < 85) return 'bg-warning';
    return 'bg-danger';
}

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

    // Сеть (Используем новый конвертер бит)
    document.getElementById('netDownload').innerText = formatNetworkSpeed(stats.network.download);
    document.getElementById('netUpload').innerText = formatNetworkSpeed(stats.network.upload);
}

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
        
        // Предупреждающий цвет, если процесс ест слишком много
        let rowClass = (p.cpu > 50 || p.ram_percent > 30) ? 'table-warning' : '';
        tr.className = rowClass;
        
        // Обрезаем длинные пути с помощью классов text-truncate и d-inline-block
        tr.innerHTML = `
            <td class="ps-4 text-muted">${p.pid}</td>
            <td class="fw-bold text-truncate">${p.name}</td>
            <td class="text-muted text-truncate" title="${p.path}">${p.path}</td>
            <td class="text-center"><span class="badge ${p.cpu > 10 ? 'bg-danger' : 'bg-secondary'}">${p.cpu}%</span></td>
            <td class="text-center pe-4"><span class="badge ${p.ram_mb > 500 ? 'bg-warning text-dark' : 'bg-light text-dark border'}">${p.ram_mb} MB (${p.ram_percent}%)</span></td>
        `;
        tbody.appendChild(tr);
    });
}

document.getElementById('procSearch').addEventListener('input', renderProcessTable);

document.addEventListener('DOMContentLoaded', () => {
    fetchStats();
    setInterval(() => {
        if (!isPaused) fetchStats();
    }, 3000); 
});