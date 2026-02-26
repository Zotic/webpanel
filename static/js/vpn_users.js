let limitModal = null;
let currentEditingIp = null;

document.addEventListener("DOMContentLoaded", () => {
    limitModal = new bootstrap.Modal(document.getElementById('limitModal'));
    fetchUsers();
    setInterval(fetchUsers, 5000); // Автообновление списка каждые 5 сек
});

async function fetchUsers() {
    try {
        const res = await fetch('/api/vpn_users');
        if (res.status === 401) { location.reload(); return; }
        const data = await res.json();
        
        if (data.success) {
            renderUsers(data.users);
        }
    } catch (e) {
        console.error("Ошибка загрузки пользователей:", e);
    }
}

function renderUsers(users) {
    const tbody = document.getElementById('usersTableBody');
    tbody.innerHTML = '';

    if (users.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-center py-5 text-muted">Нет подключенных пользователей</td></tr>';
        return;
    }

    users.forEach(user => {
        const tr = document.createElement('tr');
        
        // Статус
        let statusBadge = user.connections > 0 
            ? '<span class="badge bg-success">ОНЛАЙН</span>' 
            : '<span class="badge bg-secondary">ОФФЛАЙН</span>';
            
        // Лимит скорости
        let limitHtml = user.limit 
            ? `<span class="badge bg-warning text-dark fw-bold px-3 py-2" style="font-size: 0.9rem;">${user.limit} Мбит/с</span>` 
            : '<span class="text-muted">Без ограничений</span>';
            
        // Кнопки
        let actionButtons = '';
        if (user.limit) {
            actionButtons = `
                <button class="btn btn-sm btn-outline-primary me-1" onclick="openLimitModal('${user.ip}', ${user.limit})">Изменить</button>
                <button class="btn btn-sm btn-danger" onclick="removeLimit('${user.ip}')">Снять</button>
            `;
        } else {
            actionButtons = `<button class="btn btn-sm btn-outline-warning" onclick="openLimitModal('${user.ip}', '')">Ограничить</button>`;
        }

        tr.innerHTML = `
            <td class="ps-4">${statusBadge}</td>
            <td class="fw-bold font-monospace text-primary">${user.ip}</td>
            <td><span class="badge bg-light text-dark border fs-6">${user.connections}</span></td>
            <td>${limitHtml}</td>
            <td class="pe-4 text-end">${actionButtons}</td>
        `;
        tbody.appendChild(tr);
    });
}

function openLimitModal(ip, currentSpeed) {
    currentEditingIp = ip;
    document.getElementById('modalIpText').innerText = ip;
    document.getElementById('speedInput').value = currentSpeed;
    limitModal.show();
}

async function applyLimit() {
    const speed = document.getElementById('speedInput').value;
    if (!speed || speed < 1) {
        alert("Введите корректную скорость (от 1 Мбит/с)");
        return;
    }
    await sendLimitRequest(currentEditingIp, parseInt(speed));
    limitModal.hide();
}

async function removeLimit(ip) {
    if (confirm(`Снять ограничения скорости для ${ip}?`)) {
        await sendLimitRequest(ip, null);
    }
}

async function sendLimitRequest(ip, speed) {
    try {
        const res = await fetch('/api/set_speed_limit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip, speed: speed })
        });
        if (res.status === 401) { location.reload(); return; }
        const data = await res.json();
        
        if (data.success) {
            fetchUsers(); // Обновляем таблицу
        }
    } catch (e) {
        console.error("Ошибка установки лимита:", e);
    }
}