/**
 * SentinelShield SOC API Client
 * Centralized service layer for communicating with the FastAPI WAF backend.
 */

const getApiBaseUrl = () => {
  // 1. Check window global configuration (allows runtime override)
  if (typeof window !== 'undefined' && window.SENTINEL_API_BASE_URL) {
    return window.SENTINEL_API_BASE_URL;
  }
  // 2. Check Vite environment variable if running under Vite bundler
  try {
    if (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_API_BASE_URL) {
      return import.meta.env.VITE_API_BASE_URL;
    }
  } catch (e) {
    // Ignore if not in ESM / Vite context
  }
  // 3. If running on same port as backend or proxy, use relative path, otherwise default to local FastAPI
  if (typeof window !== 'undefined' && window.location.port === '8000') {
    return '';
  }
  return 'http://127.0.0.1:8000';
};

const BASE_URL = getApiBaseUrl();

async function request(endpoint, options = {}) {
  const url = `${BASE_URL}${endpoint}`;
  const defaultHeaders = {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
  };

  const config = {
    ...options,
    headers: {
      ...defaultHeaders,
      ...options.headers,
    },
  };

  try {
    const response = await fetch(url, config);
    if (!response.ok) {
      const errorBody = await response.json().catch(() => ({}));
      const error = new Error(errorBody.detail || errorBody.message || errorBody.error || `HTTP ${response.status}`);
      error.status = response.status;
      error.data = errorBody;
      throw error;
    }
    return await response.json();
  } catch (err) {
    console.warn(`[SentinelShield API Error] ${endpoint}:`, err.message);
    throw err;
  }
}

const SentinelAPI = {
  // Dashboard
  getStats: () => request('/api/dashboard/stats'),
  getTrafficChart: () => request('/api/dashboard/traffic'),
  getAttackDistribution: () => request('/api/dashboard/attack-distribution'),
  getTopIPs: () => request('/api/dashboard/top-ips'),

  // Traffic
  getTraffic: (params = {}) => {
    const query = new URLSearchParams(params).toString();
    return request(`/api/traffic${query ? '?' + query : ''}`);
  },
  getTrafficEvent: (id) => request(`/api/traffic/${id}`),

  // Detection & Testing
  inspectPayload: (data) => request('/api/detection/inspect', {
    method: 'POST',
    body: JSON.stringify(data)
  }),
  getSecurityEvents: (params = {}) => {
    const query = new URLSearchParams(params).toString();
    return request(`/api/detection/events${query ? '?' + query : ''}`);
  },
  getDetectionRules: () => request('/api/detection/rules'),

  // Alerts
  getAlerts: (params = {}) => {
    const query = new URLSearchParams(params).toString();
    return request(`/api/alerts${query ? '?' + query : ''}`);
  },
  getAlert: (id) => request(`/api/alerts/${id}`),
  updateAlertStatus: (id, data) => request(`/api/alerts/${id}`, {
    method: 'PATCH',
    body: JSON.stringify(data)
  }),
  addAlertNote: (id, noteData) => request(`/api/alerts/${id}/notes`, {
    method: 'POST',
    body: JSON.stringify(noteData)
  }),

  // Logs
  getLogs: (params = {}) => {
    const query = new URLSearchParams(params).toString();
    return request(`/api/logs${query ? '?' + query : ''}`);
  },

  // IP Management
  getIPs: (blockedOnly = false) => request(`/api/ips?blocked_only=${blockedOnly}`),
  getIP: (ip) => request(`/api/ips/${encodeURIComponent(ip)}`),
  blockIP: (ip, reason) => request('/api/ips/blocklist', {
    method: 'POST',
    body: JSON.stringify({ ip_address: ip, reason: reason || 'SOC Manual Block' })
  }),
  unblockIP: (ip) => request(`/api/ips/blocklist/${encodeURIComponent(ip)}`, {
    method: 'DELETE'
  }),

  // Rate Limiting
  getRateLimits: () => request('/api/rate-limits'),
  updateRateLimits: (config) => request('/api/rate-limits', {
    method: 'PUT',
    body: JSON.stringify(config)
  }),

  // WAF Rules
  getWAFRules: () => request('/api/waf/rules'),
  createWAFRule: (rule) => request('/api/waf/rules', {
    method: 'POST',
    body: JSON.stringify(rule)
  }),
  toggleWAFRule: (ruleId, updates) => request(`/api/waf/rules/${ruleId}`, {
    method: 'PATCH',
    body: JSON.stringify(updates)
  }),

  // Reports
  getReportSummary: () => request('/api/reports/summary'),
  getExportUrl: (format = 'csv') => `${BASE_URL}/api/reports/export?format=${format}`,

  // Health
  getHealth: () => request('/api/health')
};

// Expose globally on window for browser scripts
if (typeof window !== 'undefined') {
  window.SentinelAPI = SentinelAPI;
}
