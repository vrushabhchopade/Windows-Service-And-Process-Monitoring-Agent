// Investigation Workbench JavaScript

document.addEventListener("DOMContentLoaded", function () {
    loadInvestigationData("WIN-EDR-AGENT-01");
});

function loadInvestigationData(hostname) {
    fetch(`/api/v1/investigation/${hostname}/process-tree/`)
        .then(res => res.json())
        .then(data => {
            renderProcessTree(data.processes || []);
            renderAlertTimeline(data.alerts || []);
            renderRelatedEvents(data.events || []);
        })
        .catch(err => console.error("Error loading investigation tree:", err));
}

function renderProcessTree(processes) {
    const treeContainer = document.getElementById("process-tree-container");
    if (!treeContainer) return;

    treeContainer.innerHTML = "";
    if (processes.length === 0) {
        treeContainer.innerHTML = '<div class="text-muted p-3">No process hierarchy captured for host</div>';
        return;
    }

    // Build parent-child hierarchy map
    const map = {};
    const roots = [];

    processes.forEach(p => {
        map[p.pid] = { ...p, children: [] };
    });

    processes.forEach(p => {
        if (p.ppid in map) {
            map[p.ppid].children.push(map[p.pid]);
        } else {
            roots.push(map[p.pid]);
        }
    });

    const ul = document.createElement("ul");
    ul.className = "list-unstyled ps-0";

    roots.slice(0, 8).forEach(root => {
        ul.appendChild(createTreeNode(root));
    });

    treeContainer.appendChild(ul);
}

function createTreeNode(node) {
    const li = document.createElement("li");
    li.className = "mb-2 ps-3 border-start border-cyan";
    
    let isBad = node.is_in_temp || node.name.toLowerCase() === "mimikatz.exe" || node.name.toLowerCase() === "powershell.exe";
    let badge = isBad ? '<span class="badge badge-critical ms-2">SUSPICIOUS</span>' : '';

    li.innerHTML = `
        <div class="p-2 bg-container-high border border-secondary mb-1">
            <span class="mono-font text-cyan">PID ${node.pid}</span> | 
            <strong>${escapeHtml(node.name)}</strong> ${badge}
            <div class="mono-font text-muted small">${escapeHtml(node.cmdline || node.exe_path)}</div>
        </div>
    `;

    if (node.children && node.children.length > 0) {
        const childUl = document.createElement("ul");
        childUl.className = "list-unstyled ps-3 border-start border-secondary";
        node.children.forEach(child => {
            childUl.appendChild(createTreeNode(child));
        });
        li.appendChild(childUl);
    }

    return li;
}

function renderAlertTimeline(alerts) {
    const timelineEl = document.getElementById("investigation-alerts-timeline");
    if (!timelineEl) return;

    timelineEl.innerHTML = "";
    alerts.forEach(a => {
        const div = document.createElement("div");
        div.className = "p-2 mb-2 bg-container-high border-start border-3 border-danger";
        div.innerHTML = `
            <div class="d-flex justify-content-between">
                <strong class="text-danger">${escapeHtml(a.title)}</strong>
                <span class="mono-font text-muted small">${new Date(a.timestamp).toLocaleTimeString()}</span>
            </div>
            <div class="small text-light">${escapeHtml(a.description)}</div>
        `;
        timelineEl.appendChild(div);
    });
}

function renderRelatedEvents(events) {
    const eventsEl = document.getElementById("investigation-events-list");
    if (!eventsEl) return;

    eventsEl.innerHTML = "";
    events.forEach(e => {
        const div = document.createElement("div");
        div.className = "p-2 mb-2 bg-container-high border border-secondary";
        div.innerHTML = `
            <div class="d-flex justify-content-between">
                <span class="mono-font text-cyan">Event ID ${e.event_id} (${e.source})</span>
                <span class="mono-font text-muted small">${new Date(e.timestamp).toLocaleTimeString()}</span>
            </div>
            <div class="small text-muted">${escapeHtml(e.message)}</div>
        `;
        eventsEl.appendChild(div);
    });
}

function escapeHtml(text) {
    if (!text) return '';
    return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
