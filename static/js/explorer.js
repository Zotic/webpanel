{% extends "base.html" %}

{% block content %}
<div class="d-flex justify-content-between align-items-center mb-3 flex-wrap gap-2">
    <h2 class="fw-bold text-secondary mb-0">ZX Explorer</h2>
</div>

<div class="card border-0 shadow-sm" style="height: calc(100vh - 120px); display: flex; flex-direction: column;">
    
    <!-- Панель инструментов (Toolbar) -->
    <div class="card-header bg-white py-3 border-bottom d-flex flex-wrap gap-2 align-items-center">
        <!-- Навигация -->
        <button class="btn btn-sm btn-light border d-flex align-items-center" onclick="loadPath('/')" title="В корень"><span class="material-symbols-outlined fs-5">home</span></button>
        <button class="btn btn-sm btn-light border d-flex align-items-center" onclick="goUp()" title="Вверх"><span class="material-symbols-outlined fs-5">arrow_upward</span></button>
        
        <!-- Хлебные крошки -->
        <div id="breadcrumbs" class="d-flex align-items-center bg-light border px-3 rounded flex-grow-1" style="height: 31px; overflow-x: auto; white-space: nowrap; font-family: monospace; font-size: 0.9rem;">
            /
        </div>

        <div class="vr mx-1"></div>

        <!-- Создание и Загрузка -->
        <button class="btn btn-sm btn-primary d-flex align-items-center gap-1" onclick="promptCreate('folder')"><span class="material-symbols-outlined fs-6">create_new_folder</span> Папка</button>
        <button class="btn btn-sm btn-outline-primary d-flex align-items-center gap-1" onclick="promptCreate('file')"><span class="material-symbols-outlined fs-6">note_add</span> Файл</button>
        <button class="btn btn-sm btn-success d-flex align-items-center gap-1" onclick="document.getElementById('uploadInput').click()"><span class="material-symbols-outlined fs-6">upload</span> Загрузить</button>
        <input type="file" id="uploadInput" multiple style="display: none;" onchange="uploadFiles(this)">

        <div class="vr mx-1"></div>

        <!-- Операции над выделенными файлами -->
        <div class="dropdown">
            <button class="btn btn-sm btn-secondary dropdown-toggle d-flex align-items-center gap-1" type="button" data-bs-toggle="dropdown" id="actionBtn" disabled>
                Действия
            </button>
            <ul class="dropdown-menu shadow">
                <li><a class="dropdown-item d-flex align-items-center gap-2" href="#" onclick="copyCutSelected('copy')"><span class="material-symbols-outlined fs-6">content_copy</span> Копировать</a></li>
                <li><a class="dropdown-item d-flex align-items-center gap-2" href="#" onclick="copyCutSelected('cut')"><span class="material-symbols-outlined fs-6">content_cut</span> Вырезать</a></li>
                <li><hr class="dropdown-divider"></li>
                <li><a class="dropdown-item d-flex align-items-center gap-2" href="#" onclick="promptRename()"><span class="material-symbols-outlined fs-6">edit</span> Переименовать</a></li>
                <li><a class="dropdown-item d-flex align-items-center gap-2" href="#" onclick="archiveSelected()"><span class="material-symbols-outlined fs-6">folder_zip</span> В архив (Zip)</a></li>
                <li><a class="dropdown-item d-flex align-items-center gap-2 text-danger" href="#" onclick="deleteSelected()"><span class="material-symbols-outlined fs-6">delete</span> Удалить</a></li>
            </ul>
        </div>
        
        <button class="btn btn-sm btn-warning d-flex align-items-center gap-1" id="pasteBtn" style="display: none;" onclick="pasteItems()"><span class="material-symbols-outlined fs-6">content_paste</span> Вставить (<span id="pasteCount">0</span>)</button>
    </div>

    <!-- Таблица файлов -->
    <div class="card-body p-0" style="overflow-y: auto; flex-grow: 1;">
        <table class="table table-hover align-middle mb-0" style="font-size: 0.9rem;">
            <thead class="table-light position-sticky top-0" style="z-index: 10;">
                <tr>
                    <th style="width: 40px;" class="text-center"><input type="checkbox" class="form-check-input" id="selectAll" onchange="toggleSelectAll(this)"></th>
                    <th>Имя файла</th>
                    <th style="width: 120px;">Размер</th>
                    <th style="width: 150px;">Изменен</th>
                    <th style="width: 100px;" class="text-center">Опции</th>
                </tr>
            </thead>
            <tbody id="fileList">
                <tr><td colspan="5" class="text-center py-5 text-muted">Загрузка...</td></tr>
            </tbody>
        </table>
    </div>
</div>

<!-- Модальное окно: Универсальный текстовый редактор -->
<div class="modal fade" id="textEditorModal" tabindex="-1" data-bs-backdrop="static">
    <div class="modal-dialog modal-xl modal-dialog-scrollable">
        <div class="modal-content bg-dark text-white" style="border-radius: 12px; border: none; box-shadow: 0 10px 40px rgba(0,0,0,0.5);">
            <div class="modal-header border-bottom-0 p-3 align-items-center">
                <span class="material-symbols-outlined text-primary me-2">edit_document</span>
                <input type="text" id="editorFilePath" class="form-control form-control-sm bg-dark text-white border-secondary font-monospace" style="max-width: 500px;">
                <button type="button" class="btn-close btn-close-white ms-auto" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body p-0">
                <textarea id="editorContent" class="form-control bg-dark text-success font-monospace" style="height: 70vh; border: none; border-radius: 0; font-size: 0.85rem; resize: none;" spellcheck="false"></textarea>
            </div>
            <div class="modal-footer border-top-0 py-2">
                <span id="editorStatus" class="text-muted small me-auto"></span>
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Закрыть</button>
                <button type="button" class="btn btn-primary d-flex align-items-center gap-1" onclick="saveTextFile()"><span class="material-symbols-outlined fs-6">save</span> Сохранить</button>
            </div>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script src="/static/js/explorer.js"></script>
{% endblock %}