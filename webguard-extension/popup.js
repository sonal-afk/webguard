// popup.js  —  WebGuard Extension Popup

const BACKEND = 'http://127.0.0.1:5000';

// ── Check backend status ─────────────────────────────────────

async function checkBackend() {
    try {
        const r = await fetch(`${BACKEND}/`, { signal: AbortSignal.timeout(2000) });
        return r.ok;
    } catch {
        return false;
    }
}

// ── Helpers ──────────────────────────────────────────────────

function esc(s) {
    return String(s)
        .replace(/&/g,'&amp;').replace(/</g,'&lt;')
        .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function timeAgo(ts) {
    const s = Math.floor((Date.now() - ts) / 1000);
    if (s < 5)  return 'just now';
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s/60)}m ago`;
    return `${Math.floor(s/3600)}h ago`;
}

// ── Render functions ─────────────────────────────────────────

function renderOffline() {
    document.getElementById('statusDot').className = 'status-dot offline';
    document.getElementById('mainContent').innerHTML = `
        <div class="offline-msg">
            <p>⚠ Backend offline</p>
            <small>Make sure backend.py is running:<br>
            <code style="color:var(--accent)">python backend.py</code></small>
        </div>`;
}

function renderIdle() {
    document.getElementById('statusDot').className = 'status-dot online';
    document.getElementById('mainContent').innerHTML = `
        <div class="idle-msg">
            <div class="idle-icon">🔍</div>
            <div class="idle-text">No scans yet.<br>Browse any website and<br>WebGuard will monitor it automatically.</div>
        </div>`;
}

function renderResult(record) {
    document.getElementById('statusDot').className = 'status-dot online';

    const scan    = record.scanResult;
    const ai      = record.aiResult;
    const isVuln  = scan?.vulnerable;
    const isReview = !isVuln && (scan?.needs_review || scan?._suspect);
    const cls     = isVuln ? 'vuln' : isReview ? 'warn' : 'safe';
    const pct     = ((scan?.confidence || 0) * 100).toFixed(1);
    const patterns = scan?.patterns || [];

    let html = '';

    // ── Verdict card ──
    html += `
    <div class="verdict-card ${cls}">
        <div class="verdict-header">
            <div class="verdict-badge ${cls}">${isVuln ? '🚨 VULNERABLE' : isReview ? '⚠️ NEEDS REVIEW' : '✅ SAFE'}</div>
            <div class="conf-wrap">
                <div class="conf-label">Confidence</div>
                <div class="conf-track">
                    <div class="conf-fill ${cls}" id="confFill" style="width:0%"></div>
                </div>
            </div>
            <div class="conf-pct">${pct}%</div>
        </div>
        <div class="verdict-body">
            <div class="source-row">📍 ${esc(record.source || 'Unknown')} · ${timeAgo(record.timestamp)}</div>`;

    if (patterns.length > 0) {
        html += `<div class="patterns-wrap">`;
        patterns.forEach(p => {
            html += `<span class="pattern-chip">
                ${esc(p.type)}
                <span class="sev sev-${esc(p.severity)}">${esc(p.severity)}</span>
            </span>`;
        });
        html += `</div>`;
    }

    html += `</div></div>`;

    // ── Input preview ──
    html += `
    <div class="input-preview">${esc(record.input || '')}</div>`;

    // ── AI explanation ──
    html += `<div class="ai-section">
        <div class="ai-head">
            <span>🤖</span>
            <span class="ai-head-title">AI Security Analyst</span>
        </div>`;

    if (!ai) {
        html += `<div class="ai-loading">
            <div class="ai-ring"></div>
            Waiting for AI analysis…
        </div>`;
    } else if (isVuln) {
        html += `<div class="ai-body">`;
        if (ai.attack_type) {
            html += `<div class="ai-label">Attack Type</div>
                     <div class="ai-value danger">${esc(ai.attack_type)}
                        ${ai.cwe ? `<span style="font-size:10px;color:var(--muted);margin-left:6px;">${esc(ai.cwe)}</span>` : ''}
                     </div>`;
        }
        if (ai.explanation) {
            html += `<div class="ai-label">What's happening</div>
                     <div class="ai-value">${esc(ai.explanation)}</div>`;
        }
        if (ai.what_attacker_gets) {
            html += `<div class="ai-label">Attacker gains</div>
                     <div class="ai-value warn">${esc(ai.what_attacker_gets)}</div>`;
        }
        if (ai.prevention && ai.prevention.length) {
            html += `<div class="ai-label">How to fix</div>
                     <ul class="prev-list">`;
            ai.prevention.forEach((item, i) => {
                html += `<li><span class="prev-num">${i+1}.</span><span>${esc(item)}</span></li>`;
            });
            html += `</ul>`;
        }
        html += `</div>`;
    } else {
        html += `<div class="ai-body">`;
        if (ai.explanation) {
            html += `<div class="ai-label">Why it's safe</div>
                     <div class="ai-value">${esc(ai.explanation)}</div>`;
        }
        if (ai.still_watch_for) {
            html += `<div class="ai-label">Still watch for</div>
                     <div class="ai-value warn">${esc(ai.still_watch_for)}</div>`;
        }
        html += `</div>`;
    }

    html += `</div>`; // close ai-section

    document.getElementById('mainContent').innerHTML = html;

    // Animate confidence bar
    requestAnimationFrame(() => {
        const fill = document.getElementById('confFill');
        if (fill) fill.style.width = pct + '%';
    });
}

// ── Actions ──────────────────────────────────────────────────

function openDashboard() {
    chrome.tabs.create({ url: `${BACKEND}` });
}

function clearHistory() {
    chrome.storage.local.set({ history: [], lastScan: null });
    renderIdle();
}

// The extension never fires payloads at a target itself — it only flags and
// hands off. This opens the app to its guided, authorization-gated scan
// workflow for the current tab's URL; the app enforces the allowlist and
// walks the analyst through recon → select → test → review → report.
async function openGuidedScan() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const url = tab?.url;

    if (!url || url.startsWith('chrome://')) {
        document.getElementById('mainContent').innerHTML = `
            <div style="margin:12px;padding:12px;background:rgba(255,59,92,.07);border:1px solid rgba(255,59,92,.2);border-radius:8px;font-family:var(--mono);font-size:11px;color:var(--danger);">
                Cannot scan this page. Navigate to a website first.
            </div>`;
        return;
    }

    chrome.tabs.create({ url: `${BACKEND}/?deep_scan=${encodeURIComponent(url)}` });
}

// ── Init ─────────────────────────────────────────────────────

async function init() {
    const online = await checkBackend();

    if (!online) {
        renderOffline();
        return;
    }

    chrome.storage.local.get({ lastScan: null }, (data) => {
        if (data.lastScan && data.lastScan.scanResult) {
            renderResult(data.lastScan);
        } else {
            renderIdle();
        }
    });

    // Live-update popup when background finishes AI analysis
    chrome.storage.onChanged.addListener((changes, area) => {
        if (area !== 'local' || !changes.lastScan) return;
        const record = changes.lastScan.newValue;
        if (record && record.scanResult) {
            renderResult(record);
        }
    });
}

// Wire buttons (CSP blocks inline onclick — must use addEventListener)
document.getElementById('guidedScanBtn').addEventListener('click', openGuidedScan);
document.getElementById('dashboardBtn').addEventListener('click', openDashboard);
document.getElementById('clearBtn').addEventListener('click', clearHistory);

init();
