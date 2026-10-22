// Processes Explorer JavaScript

document.addEventListener("DOMContentLoaded", function () {
    loadProcesses();
    
    const searchInput = document.getElementById("process-search-input");
    if (searchInput) {
        searchInput.addEventListener("keyup", function (e) {
            loadProcesses(e.target.value);
        });
    }
});

function loadProcesses(searchQuery = "") {
    let url = "/api/v1/processes/";
    if (searchQuery) {
        url += "?search=" + encodeURIComponent(searchQuery);
    }

    fetch(url)
        .then(res => res.json())
        .then(data => {
            const procs = data.results || data;
            const tbody = document.getElementById("processes-tbody");
            if (!tbody) return;

            tbody.innerHTML = "";
            if (procs.length === 0) {
                tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No running processes found matching query</td></tr>';
                return;
            }

            procs.forEach(p => {
                const tr = document.createElement("tr");
                const isTemp = p.is_in_temp ? '<span class="badge badge-high">TEMP PATH</span>' : '<span class="badge badge-low">Normal</span>';
                const isSigned = p.is_signed ? '<span class="text-success">Signed</span>' : '<span class="text-warning">Unsigned</span>';

                tr.innerHTML = `
                    <td class="mono-font">${p.pid}</td>
                    <td class="mono-font">${p.ppid}</td>
                    <td><strong>${escapeHtml(p.name)}</strong></td>
                    <td class="mono-font text-muted">${escapeHtml(p.parent_name || 'N/A')}</td>
                    <td class="mono-font">${escapeHtml(p.username)}</td>
                    <td class="mono-font text-truncate" style="max-width: 250px;" title="${escapeHtml(p.exe_path)}">${escapeHtml(p.exe_path)}</td>
                    <td>${isTemp}</td>
                    <td>
                        <button class="cyber-btn-outline py-1 px-2" onclick="showProcessDetail(${p.pid}, '${escapeHtml(p.name)}', '${escapeHtml(p.parent_name)}', '${escapeHtml(p.exe_path).replace(/'/g, "\\'")}', '${escapeHtml(p.cmdline).replace(/'/g, "\\'")}')">Details</button>
                    </td>
                `;
                tbody.appendChild(tr);
            });
        })
        .catch(err => console.error("Error loading processes:", err));
}

function showProcessDetail(pid, name, parentName, exePath, cmdline) {
    document.getElementById("modal-pid").innerText = pid;
    document.getElementById("modal-name").innerText = name;
    document.getElementById("modal-parent").innerText = parentName || "N/A";
    document.getElementById("modal-path").innerText = exePath || "N/A";
    document.getElementById("modal-cmdline").innerText = cmdline || "N/A";
    
    const modalEl = document.getElementById("processDetailModal");
    if (modalEl) {
        const modal = new bootstrap.Modal(modalEl);
        modal.show();
    }
}

function escapeHtml(text) {
    if (!text) return '';
    return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
