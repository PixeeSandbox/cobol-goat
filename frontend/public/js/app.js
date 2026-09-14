/**
 * COBOLBank — Shared Application JavaScript
 * Enterprise Financial Services Portal
 */

'use strict';

// ── Auth helpers ────────────────────────────────────────────
function checkAuth() {
  const session = sessionStorage.getItem('cobolgoat_session');
  if (!session) {
    window.location.href = getRootPath() + 'index.html';
    return null;
  }
  try {
    return JSON.parse(session);
  } catch {
    window.location.href = getRootPath() + 'index.html';
    return null;
  }
}

function getRootPath() {
  const path = window.location.pathname;
  if (path.includes('/challenges/')) return '../';
  return '';
}

function setSession(data) {
  sessionStorage.setItem('cobolgoat_session', JSON.stringify(data));
}

function getSession() {
  const raw = sessionStorage.getItem('cobolgoat_session');
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return null; }
}

function logout() {
  apiCall('/api/auth/logout', 'POST')
    .catch(() => {})
    .finally(() => {
      sessionStorage.removeItem('cobolgoat_session');
      window.location.href = getRootPath() + 'index.html';
    });
}

// ── API call wrapper ────────────────────────────────────────
async function apiCall(endpoint, method = 'GET', body = null) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
  };

  const session = getSession();
  if (session && session.token) {
    opts.headers['Authorization'] = 'Bearer ' + session.token;
  }

  if (body !== null) {
    opts.body = JSON.stringify(body);
  }

  const res = await fetch(endpoint, opts);
  const text = await res.text();

  let data;
  try { data = JSON.parse(text); }
  catch { data = { raw: text }; }

  return { ok: res.ok, status: res.status, data };
}

// ── UI: show/hide messages ──────────────────────────────────
function showError(msg, containerId = 'error-msg') {
  const el = document.getElementById(containerId);
  if (!el) return;
  el.textContent = msg;
  el.classList.add('visible');
}

function hideError(containerId = 'error-msg') {
  const el = document.getElementById(containerId);
  if (el) el.classList.remove('visible');
}

function showSuccess(msg, containerId = 'success-msg') {
  const el = document.getElementById(containerId);
  if (!el) return;
  el.textContent = msg;
  el.classList.add('visible');
}

function hideSuccess(containerId = 'success-msg') {
  const el = document.getElementById(containerId);
  if (el) el.classList.remove('visible');
}

// ── Flag reveal — professional security finding banner ──────
function showFlag(flagText, containerId = 'flag-box') {
  const box = document.getElementById(containerId);
  if (!box) return;
  box.innerHTML = `
    <span class="flag-emoji">&#127891;</span>
    <div>
      <div class="flag-label">Security Finding Captured</div>
      <div class="flag-text">${escapeHtml(flagText)}</div>
    </div>
  `;
  box.classList.add('visible');
  box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

  const id = document.body.dataset.challengeId;
  if (id) markCompleted(id);
}

// ── Progress / localStorage ─────────────────────────────────
function markCompleted(challengeId) {
  const completed = getCompleted();
  if (!completed.includes(challengeId)) {
    completed.push(challengeId);
    localStorage.setItem('cobolgoat_completed', JSON.stringify(completed));
  }
}

function getCompleted() {
  try {
    return JSON.parse(localStorage.getItem('cobolgoat_completed') || '[]');
  } catch { return []; }
}

function isCompleted(challengeId) {
  return getCompleted().includes(challengeId);
}

function updateProgress() {
  const completed = getCompleted();
  const total = document.querySelectorAll('.feature-card[data-challenge-id]').length;
  const done = completed.length;

  const countEl = document.getElementById('progress-count');
  const fillEl  = document.getElementById('progress-fill');
  const statDoneEl = document.getElementById('stat-done');

  if (countEl) countEl.textContent = `${done} / ${total || 12}`;
  if (fillEl) fillEl.style.width = (total > 0) ? `${Math.round((done / total) * 100)}%` : '0%';
  if (statDoneEl) statDoneEl.textContent = done;

  // Update feature card styles
  document.querySelectorAll('.feature-card[data-challenge-id]').forEach(card => {
    const id = card.dataset.challengeId;
    if (id && completed.includes(id)) {
      card.classList.add('completed');
    }
  });

  // Update sidebar links
  document.querySelectorAll('.sidebar-link[data-challenge-id]').forEach(link => {
    const id = link.dataset.challengeId;
    if (id && completed.includes(id)) link.classList.add('completed');
  });
}

// ── JSON pretty printer ─────────────────────────────────────
function displayJson(obj, containerId = 'json-output') {
  const el = document.getElementById(containerId);
  if (!el) return;
  el.innerHTML = syntaxHighlightJson(obj);
  el.classList.add('visible');
}

function syntaxHighlightJson(obj) {
  const json = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2);
  return json
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, match => {
      let cls = 'json-number';
      if (/^"/.test(match)) {
        cls = /:$/.test(match) ? 'json-key' : 'json-string';
      } else if (/true|false/.test(match)) {
        cls = 'json-bool';
      } else if (/null/.test(match)) {
        cls = 'json-null';
      }
      return `<span class="${cls}">${match}</span>`;
    });
}

// ── Collapsible sections ────────────────────────────────────
function initCollapsible() {
  document.querySelectorAll('.collapsible-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const contentId = btn.dataset.target;
      const content = document.getElementById(contentId);
      if (!content) return;
      const isOpen = content.classList.toggle('open');
      btn.classList.toggle('open', isOpen);
    });
  });
}

// ── Topbar setup ────────────────────────────────────────────
function initTopbar() {
  const session = getSession();
  const usernameEl = document.getElementById('topbar-username');
  if (usernameEl && session) usernameEl.textContent = session.username || 'user';

  const logoutBtn = document.getElementById('logout-btn');
  if (logoutBtn) logoutBtn.addEventListener('click', logout);

  const menuBtn = document.getElementById('menu-toggle');
  const sidebar = document.querySelector('.sidebar');
  if (menuBtn && sidebar) {
    menuBtn.addEventListener('click', () => sidebar.classList.toggle('open'));
    document.addEventListener('click', e => {
      if (!sidebar.contains(e.target) && e.target !== menuBtn) {
        sidebar.classList.remove('open');
      }
    });
  }
}

// ── Sidebar active link ─────────────────────────────────────
function initSidebar() {
  const path = window.location.pathname;
  document.querySelectorAll('.sidebar-link').forEach(link => {
    const href = link.getAttribute('href');
    if (href && path.endsWith(href.replace('../', '/'))) {
      link.classList.add('active');
    }
  });
  updateProgress();
}

// ── Payload click-to-fill helper ────────────────────────────
function initPayloadClicks() {
  document.querySelectorAll('.payload-code[data-target]').forEach(el => {
    el.title = 'Click to fill field';
    el.addEventListener('click', () => {
      const targetId = el.dataset.target;
      const input = document.getElementById(targetId);
      if (input) {
        input.value = el.textContent;
        input.focus();
        input.dispatchEvent(new Event('input'));
      }
    });
  });
}

// ── Escape HTML ─────────────────────────────────────────────
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── Loader button state ─────────────────────────────────────
function setButtonLoading(btn, loading) {
  if (loading) {
    btn.dataset.originalText = btn.innerHTML;
    btn.innerHTML = '<span class="loader"></span> Processing...';
    btn.disabled = true;
  } else {
    btn.innerHTML = btn.dataset.originalText || btn.innerHTML;
    btn.disabled = false;
  }
}

// ── Init on DOMContentLoaded ────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initCollapsible();
  initTopbar();
  initSidebar();
  initPayloadClicks();
});
