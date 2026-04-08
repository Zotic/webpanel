let currentPath = '/';
let clipboard = { action: null, paths: [] };
let textEditorModal = null;

document.addEventListener('DOMContentLoaded', () => {
    textEditorModal = new bootstrap.Modal(document.getElementById('textEditorModal'));
    loadPath('/');
});

// Форматирование размера
function formatBytes(bytes) {
    if (bytes === 0) return '-';
    const k = 1024, sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// Загрузка папки
async function loadPath(path) {
    document.getElementById('fileList').innerHTML = '<tr><td colspan="5" class="text-center py-5"><div class="spinner-border text-primary" role="status"></div></td></tr>';
    try {
        const res = await fetch('/api/explorer/list', {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ path: path })
        });
        if (res.status === 401) { location.reload(); return; }
        const data = await res.json();
        
        if (data.success) {
            currentPath = data.path;
            renderBreadcrumbs(data.breadcrumbs);
            renderFiles(data.items);
            updateSelectionState();
        } else { alert("Ошибка: " + data.error); }
    } catch (e) { alert("Ошибка сети"); }
}

function goUp() {
    if (currentPath !== '/') {
        let parent = currentPath.substring(0, currentPath.lastIndexOf('/')) || '/';
        loadPath(parent);
    }
}

function renderBreadcrumbs(crumbs) {
    const bc = document.getElementById('breadcrumbs');
    bc.innerHTML = '';
    crumbs.forEach((crumb, idx) => {
        let span = document.createElement('span');
        span.className = 'cursor-pointer text-primary text-decoration-underline mx-1';
        span.innerText = crumb.name;
        span.onclick = () => loadPath(crumb.path);
        bc.appendChild(span);
        if (idx < crumbs.length - 1) bc.appendChild(document.createTextNode('/'));
    });
}

function renderFiles(items) {
    const tbody = document.getElementById('fileList');
    tbody.innerHTML = '';
    document.getElementById('selectAll').checked = false;

    if (items.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-center py-4 text-muted">Папка пуста</td></tr>';
        return;
    }

    items.forEach(item => {
        const tr = document.createElement('tr');
        let icon = item.is_dir ? '<span class="material-symbols-outlined text-warning align-middle">folder</span>' : '<span class="material-symbols-outlined text-secondary align-middle">draft</span>';
        if (item.name.endsWith('.zip')) icon = '<span class="material-symbols-outlined text-danger align-middle">folder_zip</span>';
        
        let clickAction = item.is_dir ? `onclick="loadPath('${item.path}')"` : `onclick="openTextEditor('${item.path}')"`;
        
        let downloadBtn = item.is_dir ? '' : `<a href="/api/explorer/download?path=${encodeURIComponent(item.path)}" class="btn btn-sm btn-light border p-1" title="Скачать"><span class="material-symbols-outlined fs-6">download</span></a>`;
        let unzipBtn = item.name.endsWith('.zip') ? `<button class="btn btn-sm btn-light border p-1" onclick="extractArchive('${item.path}')" title="Распаковать"><span class="material-symbols-outlined fs-6">unarchive</span></button>` : '';

        tr.innerHTML = `
            <td class="text-center"><input type="checkbox" class="form-check-input item-chk" value="${item.path}" onchange="updateSelectionState()"></td>
            <td>
                <div class="d-flex align-items-center gap-2 cursor-pointer" ${clickAction}>
                    ${icon} <span class="text-truncate" style="max-width: 300px; font-weight: 500;">${item.name}</span>
                </div>
            </td>
            <td class="text-muted small">${formatBytes(item.size)}</td>
            <td class="text-muted small">${item.mtime}</td>
            <td class="text-center gap-1 d-flex justify-content-center">
                ${downloadBtn}
                ${unzipBtn}
            </td>
        `;
        tbody.appendChild(tr);
    });
}

// === ВЫДЕЛЕНИЕ И ОПЕРАЦИИ ===
function toggleSelectAll(masterChk) {
    document.querySelectorAll('.item-chk').forEach(chk => chk.checked = masterChk.checked);
    updateSelectionState();
}

function updateSelectionState() {
    const checked = document.querySelectorAll('.item-chk:checked');
    document.getElementById('actionBtn').disabled = checked.length === 0;
}

function getSelectedPaths() {
    return Array.from(document.querySelectorAll('.item-chk:checked')).map(chk => chk.value);
}

async function doOperation(action, paths, dest = currentPath, newName = '') {
    try {
        const res = await fetch('/api/explorer/operate', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: action, paths: paths, dest: dest, new_name: newName })
        });
        const data = await res.json();
        if (data.success) {
            loadPath(currentPath);
            return true;
        } else { alert("Ошибка: " + data.error); return false; }
    } catch(e) { alert("Сбой сети"); return false; }
}

function promptCreate(type) {
    let name = prompt(`Введите имя ${type === 'folder' ? 'папки' : 'файла'}:`);
    if (name) doOperation(`create_${type}`, [], currentPath, name);
}

function promptRename() {
    const paths = getSelectedPaths();
    if (paths.length !== 1) { alert("Выберите только один файл для переименования."); return; }
    let currentName = paths[0].split('/').pop();
    let newName = prompt("Новое имя:", currentName);
    if (newName && newName !== currentName) doOperation('rename', paths, currentPath, newName);
}

function deleteSelected() {
    const paths = getSelectedPaths();
    if (confirm(`Удалить навсегда ${paths.length} элементов?`)) doOperation('delete', paths);
}

function archiveSelected() {
    const paths = getSelectedPaths();
    let name = prompt("Введите имя архива (например, backup.zip):", "archive.zip");
    if (name) doOperation('zip', paths, currentPath, name);
}

function extractArchive(path) {
    doOperation('unzip', [path], currentPath);
}

// === БУФЕР ОБМЕНА ===
function copyCutSelected(action) {
    clipboard = { action: action, paths: getSelectedPaths() };
    const pBtn = document.getElementById('pasteBtn');
    document.getElementById('pasteCount').innerText = clipboard.paths.length;
    pBtn.style.display = 'flex';
    pBtn.className = action === 'copy' ? 'btn btn-sm btn-primary d-flex align-items-center gap-1' : 'btn btn-sm btn-warning d-flex align-items-center gap-1';
    
    // Снимаем галочки
    document.querySelectorAll('.item-chk').forEach(c => c.checked = false);
    updateSelectionState();
}

async function pasteItems() {
    if (clipboard.paths.length === 0) return;
    let success = await doOperation(clipboard.action, clipboard.paths, currentPath);
    if (success && clipboard.action === 'cut') {
        // Очищаем буфер после успешного вырезания
        clipboard = { action: null, paths: [] };
        document.getElementById('pasteBtn').style.display = 'none';
    }
}

// === ЗАГРУЗКА ФАЙЛОВ ===
async function uploadFiles(input) {
    if (input.files.length === 0) return;
    const formData = new FormData();
    formData.append('dest', currentPath);
    for (let i = 0; i < input.files.length; i++) {
        formData.append('files[]', input.files[i]);
    }
    
    document.getElementById('fileList').innerHTML = '<tr><td colspan="5" class="text-center py-5 text-success"><div class="spinner-border spinner-border-sm"></div> Загрузка файлов...</td></tr>';
    
    try {
        const res = await fetch('/api/explorer/upload', { method: 'POST', body: formData });
        const data = await res.json();
        if (!data.success) alert("Ошибка загрузки: " + data.error);
    } catch(e) { alert("Сбой сети при загрузке"); }
    
    input.value = ''; // Сброс инпута
    loadPath(currentPath);
}

// === ТЕКСТОВЫЙ РЕДАКТОР ===
async function openTextEditor(path) {
    document.getElementById('editorFilePath').value = path;
    document.getElementById('editorContent').value = "Чтение файла...";
    document.getElementById('editorStatus').innerText = "";
    textEditorModal.show();

    try {
        const res = await fetch('/api/read_file', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: path })
        });
        const data = await res.json();
        if (data.success) document.getElementById('editorContent').value = data.content;
        else document.getElementById('editorContent').value = "Ошибка: " + data.error;
    } catch (e) { document.getElementById('editorContent').value = "Сбой сети."; }
}

async function saveTextFile() {
    const path = document.getElementById('editorFilePath').value;
    const content = document.getElementById('editorContent').value;
    const status = document.getElementById('editorStatus');
    
    status.innerHTML = '<span class="text-warning">Сохранение...</span>';
    
    try {
        const res = await fetch('/api/explorer/save_text', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: path, content: content })
        });
        const data = await res.json();
        if (data.success) {
            status.innerHTML = '<span class="text-success fw-bold">✓ Успешно сохранено</span>';
            loadPath(currentPath); // Обновляем список, если был "Save As" в текущую папку
            setTimeout(() => status.innerText = "", 3000);
        }
        else status.innerHTML = `<span class="text-danger">Ошибка: ${data.error}</span>`;
    } catch (e) { status.innerHTML = '<span class="text-danger">Сбой сети.</span>'; }
}