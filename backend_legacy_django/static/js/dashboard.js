// ============================================================
// STITCH SENTINEL - LIVE SOC DASHBOARD
// ============================================================

document.addEventListener("DOMContentLoaded", function () {
    initDashboard();
});


// ============================================================
// GLOBAL STATE
// ============================================================

let cpuChartInstance = null;
let severityChartInstance = null;

// LIVE refresh every 1 second
const LIVE_REFRESH_INTERVAL = 1000;

let cpuHistory = [];
let ramHistory = [];
let timeHistory = [];


// ============================================================
// DASHBOARD INITIALIZATION
// ============================================================

function initDashboard() {

    console.log("[+] Stitch Sentinel Live Dashboard Started");

    fetchAnalyticsData();
    fetchRecentAlerts();
    fetchEndpoints();

    // --------------------------------------------------------
    // LIVE REFRESH
    // --------------------------------------------------------

    setInterval(function () {

        fetchAnalyticsData();
        fetchRecentAlerts();
        fetchEndpoints();

    }, LIVE_REFRESH_INTERVAL);
}


// ============================================================
// ANALYTICS DATA
// ============================================================

function fetchAnalyticsData() {

    fetch(
        "/api/v1/analytics/overview/",
        {
            cache: "no-store"
        }
    )

        .then(response => {

            if (!response.ok) {
                throw new Error(
                    `Analytics API returned HTTP ${response.status}`
                );
            }

            return response.json();
        })

        .then(data => {

            // ------------------------------------------------
            // TOTAL ALERTS
            // ------------------------------------------------

            const totalAlerts =
                document.getElementById(
                    "metric-total-alerts"
                );

            if (totalAlerts) {

                updateMetric(
                    totalAlerts,
                    data.total_alerts || 0
                );
            }


            // ------------------------------------------------
            // ACTIVE PROCESSES
            // ------------------------------------------------

            const activeProcesses =
                document.getElementById(
                    "metric-active-procs"
                );

            if (activeProcesses) {

                updateMetric(
                    activeProcesses,
                    data.total_processes || 0
                );
            }


            // ------------------------------------------------
            // SUSPICIOUS SERVICES
            // ------------------------------------------------

            const suspiciousServices =
                document.getElementById(
                    "metric-suspicious-svc"
                );

            if (suspiciousServices) {

                updateMetric(
                    suspiciousServices,
                    data.suspicious_services || 0
                );
            }


            // ------------------------------------------------
            // CPU / RAM
            // ------------------------------------------------

            if (data.health) {

                const cpuMetric =
                    document.getElementById(
                        "metric-cpu-percent"
                    );

                const ramMetric =
                    document.getElementById(
                        "metric-ram-percent"
                    );


                const cpu =
                    Number(
                        data.health.cpu_percent || 0
                    );

                const ram =
                    Number(
                        data.health.ram_percent || 0
                    );


                if (cpuMetric) {

                    updateMetric(
                        cpuMetric,
                        cpu.toFixed(1) + "%"
                    );
                }


                if (ramMetric) {

                    updateMetric(
                        ramMetric,
                        ram.toFixed(1) + "%"
                    );
                }


                // ------------------------------------------------
                // LIVE CPU / RAM GRAPH
                // ------------------------------------------------

                updateCPUHistory(
                    cpu,
                    ram
                );
            }


            // ------------------------------------------------
            // SEVERITY CHART
            // ------------------------------------------------

            renderSeverityChart(
                data.severity_counts
            );

        })

        .catch(err => {

            console.error(
                "[LIVE] Error fetching analytics:",
                err
            );
        });
}


// ============================================================
// LIVE METRIC UPDATE
// ============================================================

function updateMetric(element, value) {

    const oldValue =
        element.innerText;

    const newValue =
        String(value);


    if (oldValue !== newValue) {

        element.classList.remove(
            "live-value-update"
        );

        // Force browser reflow
        void element.offsetWidth;

        element.classList.add(
            "live-value-update"
        );

        element.innerText =
            newValue;

    } else {

        element.innerText =
            newValue;
    }
}


// ============================================================
// CPU / RAM HISTORY
// ============================================================

function updateCPUHistory(
    cpu,
    ram
) {

    const now =
        new Date();

    const timeLabel =
        now.toLocaleTimeString(
            [],
            {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit"
            }
        );


    cpuHistory.push(
        Number(cpu)
    );

    ramHistory.push(
        Number(ram)
    );

    timeHistory.push(
        timeLabel
    );


    // Keep latest 30 readings
    if (cpuHistory.length > 30) {

        cpuHistory.shift();
        ramHistory.shift();
        timeHistory.shift();
    }


    renderCPUChart();
}


// ============================================================
// ENDPOINT MONITORING
// ============================================================

function fetchEndpoints() {

    fetch(
        "/api/v1/endpoints/",
        {
            cache: "no-store"
        }
    )

        .then(response => {

            if (!response.ok) {

                throw new Error(
                    `Endpoint API returned HTTP ${response.status}`
                );
            }

            return response.json();
        })

        .then(data => {

            const endpoints =
                Array.isArray(data)
                    ? data
                    : (
                        data.results || []
                    );


            // ------------------------------------------------
            // ONLINE ENDPOINT COUNT
            // ------------------------------------------------

            const onlineEndpoints =
                endpoints.filter(
                    endpoint =>
                        endpoint.is_online === true
                );


            const onlineCount =
                onlineEndpoints.length;


            const onlineMetric =
                document.getElementById(
                    "metric-online-endpoints"
                );


            if (onlineMetric) {

                updateMetric(
                    onlineMetric,
                    onlineCount
                );
            }


            // ------------------------------------------------
            // ENDPOINT TABLE
            // ------------------------------------------------

            renderEndpointTable(
                endpoints
            );

        })

        .catch(err => {

            console.error(
                "[LIVE] Error fetching endpoints:",
                err
            );
        });
}


// ============================================================
// ENDPOINT TABLE
// ============================================================

function renderEndpointTable(
    endpoints
) {

    const tbody =
        document.getElementById(
            "endpoints-tbody"
        );


    if (!tbody) {
        return;
    }


    tbody.innerHTML = "";


    if (endpoints.length === 0) {

        tbody.innerHTML = `
            <tr>
                <td
                    colspan="6"
                    class="text-center text-muted"
                >
                    No endpoints registered
                </td>
            </tr>
        `;

        return;
    }


    endpoints.forEach(
        endpoint => {

            const statusClass =
                endpoint.is_online
                    ? "text-success"
                    : "text-danger";


            const statusText =
                endpoint.is_online
                    ? "ONLINE"
                    : "OFFLINE";


            const lastSeen =
                endpoint.last_seen
                    ? new Date(
                        endpoint.last_seen
                    ).toLocaleString()
                    : "Never";


            const tr =
                document.createElement(
                    "tr"
                );


            tr.innerHTML = `

                <td>
                    <strong>
                        ${escapeHtml(
                            endpoint.hostname
                        )}
                    </strong>
                </td>

                <td class="mono-font">
                    ${escapeHtml(
                        endpoint.agent_id
                    )}
                </td>

                <td>
                    ${escapeHtml(
                        endpoint.username ||
                        "N/A"
                    )}
                </td>

                <td>
                    ${escapeHtml(
                        endpoint.ip_address ||
                        "N/A"
                    )}
                </td>

                <td>
                    <span
                        class="${statusClass}"
                    >
                        ● ${statusText}
                    </span>
                </td>

                <td class="mono-font">
                    ${escapeHtml(
                        lastSeen
                    )}
                </td>

            `;


            tbody.appendChild(
                tr
            );
        }
    );
}


// ============================================================
// RECENT SECURITY ALERTS
// ============================================================

function fetchRecentAlerts() {

    fetch(
        "/api/v1/alerts/?limit=5",
        {
            cache: "no-store"
        }
    )

        .then(response => {

            if (!response.ok) {

                throw new Error(
                    `Alerts API returned HTTP ${response.status}`
                );
            }

            return response.json();
        })

        .then(data => {

            const alerts =
                data.results ||
                data;


            const tbody =
                document.getElementById(
                    "recent-alerts-tbody"
                );


            if (!tbody) {
                return;
            }


            tbody.innerHTML = "";


            if (
                !Array.isArray(alerts) ||
                alerts.length === 0
            ) {

                tbody.innerHTML = `
                    <tr>
                        <td
                            colspan="5"
                            class="text-center text-muted"
                        >
                            No security alerts detected
                        </td>
                    </tr>
                `;

                return;
            }


            alerts.forEach(
                alert => {

                    let badgeClass =
                        "badge-low";


                    if (
                        alert.severity ===
                        "CRITICAL"
                    ) {

                        badgeClass =
                            "badge-critical";

                    }
                    else if (
                        alert.severity ===
                        "HIGH"
                    ) {

                        badgeClass =
                            "badge-high";

                    }
                    else if (
                        alert.severity ===
                        "MEDIUM"
                    ) {

                        badgeClass =
                            "badge-medium";
                    }


                    const tr =
                        document.createElement(
                            "tr"
                        );


                    tr.innerHTML = `

                        <td>
                            <span
                                class="badge ${badgeClass}"
                            >
                                ${escapeHtml(
                                    alert.severity
                                )}
                            </span>
                        </td>

                        <td>
                            <strong>
                                ${escapeHtml(
                                    alert.title
                                )}
                            </strong>
                        </td>

                        <td class="mono-font">
                            ${escapeHtml(
                                alert.hostname
                            )}
                        </td>

                        <td>
                            <span
                                class="mitre-tag"
                            >
                                ${escapeHtml(
                                    alert.mitre_technique ||
                                    "N/A"
                                )}
                            </span>
                        </td>

                        <td class="mono-font">
                            ${
                                alert.timestamp
                                    ? new Date(
                                        alert.timestamp
                                    ).toLocaleTimeString()
                                    : "N/A"
                            }
                        </td>

                    `;


                    tbody.appendChild(
                        tr
                    );
                }
            );

        })

        .catch(err => {

            console.error(
                "[LIVE] Error fetching alerts:",
                err
            );
        });
}


// ============================================================
// SEVERITY CHART
// ============================================================

function renderSeverityChart(
    counts
) {

    const ctx =
        document.getElementById(
            "severityChart"
        );


    if (!ctx) {
        return;
    }


    const critical =
        counts
            ? counts.CRITICAL || 0
            : 0;


    const high =
        counts
            ? counts.HIGH || 0
            : 0;


    const medium =
        counts
            ? counts.MEDIUM || 0
            : 0;


    const low =
        counts
            ? counts.LOW || 0
            : 0;


    if (severityChartInstance) {

        severityChartInstance
            .data
            .datasets[0]
            .data = [
                critical,
                high,
                medium,
                low
            ];


        severityChartInstance.update(
            "none"
        );

        return;
    }


    severityChartInstance =
        new Chart(
            ctx,
            {

                type: "doughnut",

                data: {

                    labels: [
                        "Critical",
                        "High",
                        "Medium",
                        "Low"
                    ],

                    datasets: [
                        {

                            data: [
                                critical,
                                high,
                                medium,
                                low
                            ],

                            backgroundColor: [
                                "#ff4d4d",
                                "#ff9100",
                                "#ffd600",
                                "#00e676"
                            ],

                            borderWidth: 1,

                            borderColor:
                                "#0d1c2d"
                        }
                    ]
                },

                options: {

                    responsive: true,

                    maintainAspectRatio:
                        false,

                    animation: {
                        duration: 500
                    },

                    plugins: {

                        legend: {

                            position:
                                "bottom",

                            labels: {

                                color:
                                    "#849396",

                                font: {

                                    family:
                                        "Inter",

                                    size: 11
                                }
                            }
                        }
                    }
                }
            }
        );
}


// ============================================================
// LIVE CPU / RAM CHART
// ============================================================

function renderCPUChart() {

    const ctx =
        document.getElementById(
            "cpuTrendChart"
        );


    if (!ctx) {
        return;
    }


    // --------------------------------------------------------
    // EXISTING CHART
    // --------------------------------------------------------

    if (cpuChartInstance) {

        cpuChartInstance
            .data
            .labels =
            [...timeHistory];


        cpuChartInstance
            .data
            .datasets[0]
            .data =
            [...cpuHistory];


        cpuChartInstance
            .data
            .datasets[1]
            .data =
            [...ramHistory];


        cpuChartInstance.update(
            "none"
        );

        return;
    }


    // --------------------------------------------------------
    // FIRST CHART CREATION
    // --------------------------------------------------------

    cpuChartInstance =
        new Chart(
            ctx,
            {

                type: "line",

                data: {

                    labels:
                        [...timeHistory],

                    datasets: [

                        {

                            label:
                                "CPU %",

                            data:
                                [...cpuHistory],

                            borderColor:
                                "#00E5FF",

                            backgroundColor:
                                "rgba(0, 229, 255, 0.10)",

                            tension:
                                0.3,

                            fill:
                                true,

                            pointRadius:
                                3,

                            pointHoverRadius:
                                5
                        },


                        {

                            label:
                                "RAM %",

                            data:
                                [...ramHistory],

                            borderColor:
                                "#2979FF",

                            backgroundColor:
                                "transparent",

                            tension:
                                0.3,

                            fill:
                                false,

                            pointRadius:
                                3,

                            pointHoverRadius:
                                5
                        }

                    ]
                },


                options: {

                    responsive:
                        true,

                    maintainAspectRatio:
                        false,

                    animation: {

                        duration:
                            500
                    },


                    scales: {

                        x: {

                            ticks: {

                                color:
                                    "#849396",

                                maxTicksLimit:
                                    10
                            },

                            grid: {

                                color:
                                    "#1c2b3c"
                            }
                        },


                        y: {

                            min:
                                0,

                            max:
                                100,

                            ticks: {

                                color:
                                    "#849396"
                            },

                            grid: {

                                color:
                                    "#1c2b3c"
                            }
                        }
                    },


                    plugins: {

                        legend: {

                            labels: {

                                color:
                                    "#849396"
                            }
                        }
                    }
                }
            }
        );
}


// ============================================================
// HTML SECURITY HELPER
// ============================================================

function escapeHtml(
    text
) {

    if (
        text === null ||
        text === undefined
    ) {

        return "";
    }


    return String(text)

        .replace(
            /&/g,
            "&amp;"
        )

        .replace(
            /</g,
            "&lt;"
        )

        .replace(
            />/g,
            "&gt;"
        )

        .replace(
            /"/g,
            "&quot;"
        )

        .replace(
            /'/g,
            "&#039;"
        );
}