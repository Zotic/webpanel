let limitModal = null;
let nameModal = null;
let ipInfoModal = null;
let currentEditingIp = null;

document.addEventListener("DOMContentLoaded", () => {
    limitModal = new bootstrap.Modal(document.getElementById('limitModal'));
    nameModal = new bootstrap.Modal(document.getElementById('nameModal'));
    ipInfoModal = new bootstrap.Modal(document.getElementById('ipInfoModal'));
    
    fetchConnections();
    setInterval(fetchConnections, 5000); 
});

async function fetchConnections() {
    try {
        const res = await fetch('/api/vpn_users');
        if (res.status === 401) { location.reload(); return; }
        const data = await res.json();
        
        if (data.success) {
            renderInbound(data.inbound);
            renderOutbound(data.outbound);
        }
    } catch (e) {
        console.error("Ошибка загрузки подключений:", e);
    }
}

// 1. Отрисовка Клиентов (Входящие)
function renderInbound(users) {
    const tbody = document.getElementById('inboundTableBody');
    tbody.innerHTML = '';

    if (users.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-center py-5 text-muted">Нет входящих подключений</td></tr>';
        return;
    }

    users.forEach(user => {
        const tr = document.createElement('tr');
        
        let statusBadge = user.connections > 0 
            ? '<span class="badge bg-success w-100">ОНЛАЙН</span>' 
            : '<span class="badge bg-secondary w-100">ОФФЛАЙН</span>';
            
        let limitHtml = user.limit 
            ? `<span class="badge bg-warning text-dark fw-bold px-3 py-2" style="font-size: 0.9rem;">${user.limit} Мбит/с</span>` 
            : '<span class="text-muted">Без ограничений</span>';
            
        let actionButtons = '';
        if (user.limit) {
            actionButtons = `
                <button class="btn btn-sm btn-outline-primary me-1" onclick="openLimitModal('${user.ip}', ${user.limit})">Изменить лимит</button>
                <button class="btn btn-sm btn-danger" onclick="removeLimit('${user.ip}')">Снять</button>
            `;
        } else {
            actionButtons = `<button class="btn btn-sm btn-outline-warning" onclick="openLimitModal('${user.ip}', '')">Ограничить</button>`;
        }

        // Имя пользователя + Кнопка карандаша
        let rawName = user.username ? user.username.replace(/'/g, "\\'") : '';
        let userNameHtml = user.username 
            ? `<span class="fw-bold text-dark align-middle me-2">${user.username}</span>` 
            : `<span class="text-muted small align-middle me-2">Без имени</span>`;
            
        userNameHtml += `<span class="material-symbols-outlined text-primary align-middle cursor-pointer" style="font-size: 16px;" onclick="openNameModal('${user.ip}', '${rawName}')" title="Изменить имя">edit</span>`;

        tr.innerHTML = `
            <td class="text-center align-middle" style="width: 100px;">${statusBadge}</td>
            <td class="fw-bold font-monospace text-primary align-middle">
                ${user.ip}
                <span class="material-symbols-outlined text-info align-middle ms-1 cursor-pointer" style="font-size: 18px;" onclick="showIpInfo('${user.ip}')" title="Инфо">help</span>
            </td>
            <td class="align-middle">${userNameHtml}</td>
            <td class="text-center align-middle">
                <span class="badge bg-light text-success border fs-6" title="Входящие соединения">
                    <span class="material-symbols-outlined align-middle" style="font-size: 14px;">arrow_downward</span> ${user.connections}
                </span>
            </td>
            <td class="align-middle">${limitHtml}</td>
            <td class="pe-4 text-end align-middle">${actionButtons}</td>
        `;
        tbody.appendChild(tr);
    });
}

// 2. Отрисовка Сайтов (Исходящие)
function renderOutbound(sites) {
    const tbody = document.getElementById('outboundTableBody');
    tbody.innerHTML = '';

    if (sites.length === 0) {
        tbody.innerHTML = '<tr><td colspan="3" class="text-center py-5 text-muted">Нет исходящих подключений</td></tr>';
        return;
    }

    sites.forEach(site => {
        const tr = document.createElement('tr');
        
        let domainHtml = site.domain 
            ? `<br><small class="text-muted font-monospace" style="font-size: 0.8rem;">→ ${site.domain}</small>` 
            : '';
            
        let usersHtml = site.users === "Неизвестно"
            ? `<span class="text-muted small">${site.users}</span>`
            : `<span class="fw-bold text-dark">${site.users}</span>`;

        tr.innerHTML = `
            <td class="ps-4 align-middle">
                <span class="fw-bold font-monospace text-dark">${site.ip}</span>
                ${domainHtml}
            </td>
            <td class="align-middle">${usersHtml}</td>
            <td class="pe-4 text-center align-middle">
                <span class="badge bg-light text-primary border fs-6" title="Исходящие соединения">
                    <span class="material-symbols-outlined align-middle" style="font-size: 14px;">arrow_upward</span> ${site.connections}
                </span>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

// === ФУНКЦИИ ЛИМИТОВ СКОРОСТИ ===
function openLimitModal(ip, currentSpeed) {
    currentEditingIp = ip;
    document.getElementById('modalIpText').innerText = ip;
    document.getElementById('speedInput').value = currentSpeed;
    limitModal.show();
}

async function applyLimit() {
    const speed = document.getElementById('speedInput').value;
    if (!speed || speed < 1) { alert("Введите скорость от 1 Мбит/с"); return; }
    await sendLimitRequest(currentEditingIp, parseInt(speed));
    limitModal.hide();
}

async function removeLimit(ip) {
    if (confirm(`Снять ограничения скорости для ${ip}?`)) await sendLimitRequest(ip, null);
}

async function sendLimitRequest(ip, speed) {
    try {
        const res = await fetch('/api/set_speed_limit', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip, speed: speed })
        });
        if (res.status === 401) { location.reload(); return; }
        await res.json();
        fetchConnections();
    } catch (e) {}
}

// === ФУНКЦИИ ИМЕН ПОЛЬЗОВАТЕЛЕЙ ===
function openNameModal(ip, currentName) {
    currentEditingIp = ip;
    document.getElementById('modalNameIpText').innerText = ip;
    document.getElementById('nameInput').value = currentName;
    nameModal.show();
}

async function applyCustomName() {
    const name = document.getElementById('nameInput').value;
    try {
        const res = await fetch('/api/set_custom_name', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: currentEditingIp, name: name })
        });
        if (res.status === 401) { location.reload(); return; }
        await res.json();
        fetchConnections();
        nameModal.hide();
    } catch (e) {}
}

// === ФУНКЦИЯ ИНФО ОБ IP ===
async function showIpInfo(ip) {
    document.getElementById('infoIpText').innerText = ip;
    document.getElementById('ipInfoLoader').style.display = 'inline-block';
    document.getElementById('ipInfoContent').style.display = 'none';
    ipInfoModal.show();

    try {
        const res = await fetch(`/api/ip_info/${ip}`);
        if (res.status === 401) { location.reload(); return; }
        const result = await res.json();
        
        document.getElementById('ipInfoLoader').style.display = 'none';
        
        if (result.success && result.data.status === 'success') {
            document.getElementById('ipInfoContent').style.display = 'block';
            document.getElementById('infoCountry').innerText = result.data.country || 'Неизвестно';
            document.getElementById('infoCity').innerText = result.data.city || 'Неизвестно';
            document.getElementById('infoIsp').innerText = result.data.isp || 'Неизвестно';
            document.getElementById('infoOrg').innerText = result.data.org || 'Неизвестно';
        } else {
            alert('Не удалось получить информацию об IP');
            ipInfoModal.hide();
        }
    } catch (e) {
        alert('Ошибка сети при запросе');
        ipInfoModal.hide();
    }
}