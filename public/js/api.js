'use strict';
/**
 * api.js — Shared frontend API client for PenChecker
 * All pages use this to talk to the backend.
 */

const PC = {
  BASE: window.location.origin,

  // ─── Auth ────────────────────────────────────────────────────────────────
  getToken() { return localStorage.getItem('pc_token'); },
  getUser() { try { return JSON.parse(localStorage.getItem('pc_user') || 'null'); } catch { return null; } },
  isLoggedIn() { return !!this.getToken(); },

  setSession(token, user) {
    localStorage.setItem('pc_token', token);
    localStorage.setItem('pc_user', JSON.stringify(user));
  },

  logout() {
    localStorage.removeItem('pc_token');
    localStorage.removeItem('pc_user');
    window.location.href = '/login.html';
  },

  requireAuth() {
    if (!this.isLoggedIn()) window.location.href = '/login.html?expired=1';
  },

  // ─── HTTP helpers ─────────────────────────────────────────────────────────
  async request(method, path, body = null, authed = true) {
    const headers = { 'Content-Type': 'application/json' };
    if (authed) {
      const token = this.getToken();
      if (!token) { this.logout(); return; }
      headers['Authorization'] = `Bearer ${token}`;
    }

    const opts = { method, headers };
    if (body) opts.body = JSON.stringify(body);

    const res = await fetch(`${this.BASE}/api${path}`, opts);
    const data = await res.json().catch(() => ({}));

    if (res.status === 401) { this.logout(); return; }
    if (!res.ok) throw Object.assign(new Error(data.error || 'Request failed'), { status: res.status, data });

    return data;
  },

  get(path, authed = true)       { return this.request('GET', path, null, authed); },
  post(path, body, authed = true) { return this.request('POST', path, body, authed); },
  patch(path, body)              { return this.request('PATCH', path, body); },
  del(path)                      { return this.request('DELETE', path); },

  // ─── Auth methods ──────────────────────────────────────────────────────────
  async login(email, password) {
    const data = await this.post('/auth/login', { email, password }, false);
    this.setSession(data.token, data.user);
    return data;
  },

  async signup(email, password, full_name) {
    const data = await this.post('/auth/signup', { email, password, full_name }, false);
    this.setSession(data.token, data.user);
    return data;
  },

  // ─── Scans ────────────────────────────────────────────────────────────────
  startScan(params) { return this.post('/scans', params); },
  listScans(limit = 20, offset = 0) { return this.get(`/scans?limit=${limit}&offset=${offset}`); },
  getScan(id) { return this.get(`/scans/${id}`); },
  getScanProgress(id) { return this.get(`/scans/${id}/progress`); },
  deleteScan(id) { return this.del(`/scans/${id}`); },

  // ─── Domains ─────────────────────────────────────────────────────────────
  listDomains() { return this.get('/domains'); },
  addDomain(domain) { return this.post('/domains', { domain }); },
  verifyDomain(id, method) { return this.post(`/domains/${id}/verify`, { method }); },
  deleteDomain(id) { return this.del(`/domains/${id}`); },
  updateDomain(id, updates) { return this.patch(`/domains/${id}`, updates); },

  // ─── Users ───────────────────────────────────────────────────────────────
  getMe() { return this.get('/users/me'); },
  updateMe(updates) { return this.patch('/users/me', updates); },
  getStats() { return this.get('/users/stats'); },
  getFindings() { return this.get('/users/findings'); },
  getNotifications() { return this.get('/users/notifications'); },
  markNotificationRead(id) { return this.patch(`/users/notifications/${id}/read`); },
  markAllNotificationsRead() { return this.post('/users/notifications/read-all', {}); },

  // ─── AI Assistant ────────────────────────────────────────────────────────
  listAIChats() { return this.get('/users/ai-chat'); },
  createAIChat(title, scanId) { return this.post('/users/ai-chat', { session_title: title, scan_id: scanId }); },
  getAIChat(id) { return this.get(`/users/ai-chat/${id}`); },
  updateAIChat(id, messages) { return this.patch(`/users/ai-chat/${id}`, { messages }); },
  deleteAIChat(id) { return this.del(`/users/ai-chat/${id}`); },
  sendAIMessage(id, message) { return this.post(`/users/ai-chat/${id}/message`, { message }); },

  // ─── Security Badges ─────────────────────────────────────────────────────
  getLatestBadge() { return this.get('/users/badges/latest'); },
  saveBadge(domain, security_score, badge_level) { return this.post('/users/badges', { domain, security_score, badge_level }); },

  // ─── Email Utilities ──────────────────────────────────────────────────────
  sendTestEmail() { return this.post('/users/test-email', {}); },

  // ─── PDF Export ───────────────────────────────────────────────────────────
  exportPDF(scanId) {
    const token = this.getToken();
    // Trigger download by navigating to the PDF endpoint with auth header via a fetch-blob approach
    return fetch(`${this.BASE}/api/scans/${scanId}/export/pdf`, {
      headers: { 'Authorization': `Bearer ${token}` },
    }).then(res => {
      if (!res.ok) return res.json().then(d => { throw new Error(d.error || 'Export failed'); });
      return res.blob();
    }).then(blob => {
      const url = URL.createObjectURL(blob);
      const a   = document.createElement('a');
      a.href = url;
      a.download = `penchecker-report-${scanId.slice(0, 8)}.pdf`;
      document.body.appendChild(a);
      a.click();
      setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 2000);
    });
  },
};

// ─── Shared UI helpers ────────────────────────────────────────────────────────
function toast(msg, type = 'success', duration = 3500) {
  const existing = document.getElementById('pc-toast');
  if (existing) existing.remove();

  const t = document.createElement('div');
  t.id = 'pc-toast';
  t.style.cssText = `
    position:fixed; bottom:24px; right:24px; z-index:9999;
    padding:12px 20px; border-radius:10px; font-family:inherit; font-size:0.88rem;
    font-weight:600; max-width:360px; animation:toastIn 0.3s ease;
    box-shadow:0 8px 32px rgba(0,0,0,0.4);
    background:${type === 'error' ? '#ef4444' : type === 'warn' ? '#f59e0b' : '#00e5ff'};
    color:${type === 'error' || type === 'warn' ? '#fff' : '#0a0a0f'};
  `;
  t.textContent = msg;

  if (!document.getElementById('pc-toast-style')) {
    const s = document.createElement('style');
    s.id = 'pc-toast-style';
    s.textContent = '@keyframes toastIn{from{transform:translateY(20px);opacity:0}to{transform:none;opacity:1}}';
    document.head.appendChild(s);
  }

  document.body.appendChild(t);
  setTimeout(() => t.remove(), duration);
}

function severityColor(sev) {
  const map = { critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#22c55e', info: '#3b82f6' };
  return map[sev] || '#6b7280';
}

function severityBadge(sev) {
  const label = (sev || 'info').toUpperCase();
  return `<span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:0.65rem;font-weight:700;background:${severityColor(sev)}22;color:${severityColor(sev)};border:1px solid ${severityColor(sev)}55">${label}</span>`;
}

function timeAgo(dateStr) {
  if (!dateStr) return '—';
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

function formatDate(dateStr) {
  if (!dateStr) return '—';
  return new Date(dateStr).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
}

// Apply saved theme on page load
(function() {
  const theme = localStorage.getItem('pc_theme') || 'dark';
  if (theme === 'light') document.documentElement.classList.add('light-theme');
})();
