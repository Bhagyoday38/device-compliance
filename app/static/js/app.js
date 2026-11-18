const input = document.getElementById("files");
const list = document.getElementById("file-list");
const dropzone = document.getElementById("dropzone");

function formatFileSize(size) {
    if (!size) return "0 KB";
    const units = ["B", "KB", "MB", "GB"];
    let value = size;
    let unitIndex = 0;

    while (value >= 1024 && unitIndex < units.length - 1) {
        value /= 1024;
        unitIndex += 1;
    }

    return `${value.toFixed(value >= 10 || unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}

function renderFiles() {
    if (!input || !list) return;

    list.innerHTML = "";

    if (!input.files || input.files.length === 0) {
        const empty = document.createElement("div");
        empty.className = "selected-file empty-state-file";
        empty.innerHTML = "<span>No files selected</span><small>CSV or XLSX</small>";
        list.appendChild(empty);
        return;
    }

    const files = Array.from(input.files);
    const summary = document.createElement("div");
    summary.className = "selected-file summary";
    summary.innerHTML = `<span>${files.length} file${files.length > 1 ? "s" : ""} ready</span><small>${files.reduce((total, file) => total + file.size, 0) > 0 ? formatFileSize(files.reduce((total, file) => total + file.size, 0)) : "0 KB"}</small>`;
    list.appendChild(summary);

    files.forEach((file, index) => {
        const row = document.createElement("div");
        row.className = "selected-file";

        const left = document.createElement("span");
        left.textContent = `${index + 1}. ${file.name}`;

        const right = document.createElement("small");
        right.textContent = formatFileSize(file.size);

        row.appendChild(left);
        row.appendChild(right);
        list.appendChild(row);
    });
}

if (input) {
    input.addEventListener("change", renderFiles);
    input.setAttribute("aria-label", "Upload CSV or XLSX device files");
}

if (dropzone && input) {
    dropzone.addEventListener("click", (event) => {
        if (event.target !== input) {
            input.click();
        }
    });

    ["dragenter", "dragover"].forEach(eventName => {
        dropzone.addEventListener(eventName, event => {
            event.preventDefault();
            dropzone.classList.add("dragging");
        });
    });

    ["dragleave", "drop"].forEach(eventName => {
        dropzone.addEventListener(eventName, event => {
            event.preventDefault();
            dropzone.classList.remove("dragging");
        });
    });

    dropzone.addEventListener("drop", event => {
        event.preventDefault();
        const transferred = event.dataTransfer && event.dataTransfer.files;
        if (!transferred || !transferred.length) {
            return;
        }

        const dataTransfer = new DataTransfer();
        Array.from(transferred).forEach(file => dataTransfer.items.add(file));
        input.files = dataTransfer.files;
        renderFiles();
    });
}
