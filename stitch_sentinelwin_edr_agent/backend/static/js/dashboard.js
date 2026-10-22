// Stitch Sentinel Dashboard JavaScript Logic

document.addEventListener("DOMContentLoaded", function () {
    initDashboard();
});

let cpuChartInstance = null;
let severityChartInstance = null;

function initDashboard() {
    fetchAnalyticsData();
    fetchRecentAlerts();

    // Auto refresh every 10 seconds
    setInterval(function () {
        fetchAnalyticsData();
        fetchRecentAlerts();
    }, 10000);
}

function fetchAnalyticsData() {
    fetch('/api/v1/analytics/overview/')
        .then(response => response.json())
        .then(data => {
            document.getElementById('metric-total-alerts').innerText = data.total_alerts || 0;
            document.getElementById('metric-active-procs').innerText = data.total_processes || 0;
            document.getElementById('metric-suspicious-svc').innerText = data.suspicious_services || 0;

            if (data.health) {
                document.getElementById('metric-cpu-percent').innerText = (data.health.cpu_percent || 0) + '%';
                document.getElementById('metric-ram-percent').innerText = (data.health.ram_percent || 0) + '%';
            }

            renderSeverityChart(data.severity_counts);
            renderCPUChart(data.health);
        })
        .catch(err => console.error("Error fetching analytics:", err));
}

function fetchRecentAlerts() {
    fetch('/api/v1/alerts/?limit=5')
        .then(response => response.json())
        .then(data => {
            const alerts = data.results || data;
            const tbody = document.getElementById('recent-alerts-tbody');
            if (!tbody) return;

            tbody.innerHTML = '';
            if (alerts.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No security alerts detected</td></tr>';
                return;
            }

            alerts.forEach(alert => {
                let badgeClass = 'badge-low';
                if (alert.severity === 'CRITICAL') badgeClass = 'badge-critical';
                else if (alert.severity === 'HIGH') badgeClass = 'badge-high';
                else if (alert.severity === 'MEDIUM') badgeClass = 'badge-medium';

                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><span class="badge ${badgeClass}">${alert.severity}</span></td>
                    <td><strong>${escapeHtml(alert.title)}</strong></td>
                    <td class="mono-font">${escapeHtml(alert.hostname)}</td>
                    <td><span class="mitre-tag">${escapeHtml(alert.mitre_technique || 'N/A')}</span></td>
                    <td class="mono-font">${new Date(alert.timestamp).toLocaleTimeString()}</td>
                `;
                tbody.appendChild(tr);
            });
        })
        .catch(err => console.error("Error fetching recent alerts:", err));
}

function renderSeverityChart(counts) {
    const ctx = document.getElementById('severityChart');
    if (!ctx) return;

    const critical = counts ? counts.CRITICAL || 0 : 0;
    const high = counts ? counts.HIGH || 0 : 0;
    const medium = counts ? counts.MEDIUM || 0 : 0;
    const low = counts ? counts.LOW || 0 : 0;

    if (severityChartInstance) {
        severityChartInstance.data.datasets[0].data = [critical, high, medium, low];
        severityChartInstance.update();
        return;
    }

    severityChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [critical, high, medium, low],
                backgroundColor: ['#ff4d4d', '#ff9100', '#ffd600', '#00e676'],
                borderWidth: 1,
                borderColor: '#0d1c2d'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#849396', font: { family: 'Inter', size: 11 } }
                }
            }
        }
    });
}

function renderCPUChart(health) {
    const ctx = document.getElementById('cpuTrendChart');
    if (!ctx) return;

    const currentCpu = health ? health.cpu_percent || 15 : 15;
    const currentRam = health ? health.ram_percent || 45 : 45;

    if (cpuChartInstance) {
        cpuChartInstance.data.datasets[0].data.push(currentCpu);
        cpuChartInstance.data.datasets[1].data.push(currentRam);
        if (cpuChartInstance.data.datasets[0].data.length > 10) {
            cpuChartInstance.data.datasets[0].data.shift();
            cpuChartInstance.data.datasets[1].data.shift();
        }
        cpuChartInstance.update();
        return;
    }

    cpuChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: ['1m ago', '50s', '40s', '30s', '20s', '10s', 'Now'],
            datasets: [
                {
                    label: 'CPU %',
                    data: [12, 18, 25, 45, 30, 22, currentCpu],
                    borderColor: '#00E5FF',
                    backgroundColor: 'rgba(0, 229, 255, 0.1)',
                    tension: 0.3,
                    fill: true
                },
                {
                    label: 'RAM %',
                    data: [40, 42, 41, 44, 43, 45, currentRam],
                    borderColor: '#2979FF',
                    backgroundColor: 'transparent',
                    tension: 0.3
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { ticks: { color: '#849396' }, grid: { color: '#1c2b3c' } },
                y: { min: 0, max: 100, ticks: { color: '#849396' }, grid: { color: '#1c2b3c' } }
            },
            plugins: {
                legend: { labels: { color: '#849396' } }
            }
        }
    });
}

function escapeHtml(text) {
    if (!text) return '';
    return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
