// content.js  —  WebGuard Page Monitor
// Injected into every page. Watches form submissions, input changes,
// and URL parameters then forwards them to background.js for scanning.

(function () {
    'use strict';

    // Avoid injecting twice
    if (window.__webguardInjected) return;
    window.__webguardInjected = true;

    // ── Monitor form submissions ─────────────────────────────
    document.addEventListener('submit', (e) => {
        const form = e.target;
        const data = new FormData(form);
        const parts = [];

        for (const [key, val] of data.entries()) {
            if (typeof val === 'string') {
                parts.push(`${key}=${val}`);
            }
        }

        const payload = `${form.method?.toUpperCase() || 'POST'} ${form.action || window.location.href}\n${parts.join('&')}`;

        chrome.runtime.sendMessage({
            type:    'SCAN_INPUT',
            input:   payload,
            source:  'Form submission',
            pageUrl: window.location.href,
        });
    }, true);

    // ── Monitor input/textarea changes (on blur) ─────────────
    document.addEventListener('blur', (e) => {
        const el = e.target;
        if (!['INPUT', 'TEXTAREA'].includes(el.tagName)) return;
        if (['password', 'file', 'submit', 'button', 'hidden'].includes(el.type)) return;

        const val = el.value?.trim();
        if (!val || val.length < 4) return;

        chrome.runtime.sendMessage({
            type:    'SCAN_INPUT',
            input:   val,
            source:  `Input field (${el.name || el.id || el.placeholder || 'unknown'})`,
            pageUrl: window.location.href,
        });
    }, true);

    // ── Passive response-body evidence scan ──────────────────
    // Reads ONLY the text this page already rendered in your own tab.
    // No payload is ever sent to the page, and the page content itself is
    // NOT transmitted anywhere — only the *names* of any high-confidence leak
    // signatures matched locally are handed to background.js. This is the same
    // kind of observation a human does by looking at the screen.
    const EVIDENCE_SIGNATURES = [
        { type: 'SQL error (MySQL)',       re: /you have an error in your sql syntax|mysql_fetch_(array|assoc|row|object)\s*\(\)|supplied argument is not a valid mysql/i },
        { type: 'SQL error (generic)',     re: /sqlstate\s*\[|unclosed quotation mark after the character string|quoted string not properly terminated|odbc.{0,40}sql server driver|native client.{0,40}error/i },
        { type: 'SQL error (PostgreSQL)',  re: /pg_query\s*\(\)|postgresql.{0,20}error|pg::syntaxerror/i },
        { type: 'SQL error (Oracle)',      re: /\bORA-\d{5}\b|oracle.{0,20}(odbc|driver).{0,20}error/i },
        { type: 'Leaked /etc/passwd',      re: /root:.{0,20}:0:0:/ },
        { type: 'Server error / stack trace', re: /(warning|fatal error|parse error|uncaught exception):.{0,80}(on line \d+|in \/|in [a-z]:\\)/i },
    ];

    function scanPageEvidence() {
        const text = (document.body?.innerText || '').slice(0, 20000);
        if (!text) return;
        const hits = [...new Set(EVIDENCE_SIGNATURES.filter(s => s.re.test(text)).map(s => s.type))];
        if (!hits.length) return;
        chrome.runtime.sendMessage({
            type:     'PAGE_EVIDENCE',
            patterns: hits,
            pageUrl:  window.location.href,
        });
    }

    // Run once the page has settled, and again shortly after in case the
    // error/output is rendered late (e.g. after an async request).
    scanPageEvidence();
    setTimeout(scanPageEvidence, 1500);

    // ── Inline warning banner ────────────────────────────────
    const BACKEND = 'http://127.0.0.1:5000';
    let banner = null;

    function removeBanner() {
        if (banner) { banner.remove(); banner = null; }
    }

    function handoffButtonHtml(deepScanUrl, authorized) {
        if (!deepScanUrl) return '';
        const label = authorized ? '🔬 Deep Scan in WebGuard' : '🔒 Authorize &amp; Scan in WebGuard';
        const param = authorized ? 'deep_scan' : 'authorize';
        const url = `${BACKEND}/?${param}=${encodeURIComponent(deepScanUrl)}`;
        return `<button id="__wg_handoff" data-url="${url}" style="background:rgba(255,255,255,.25);border:none;color:#fff;cursor:pointer;border-radius:4px;padding:4px 10px;font-size:12px;font-weight:600;white-space:nowrap;">${label}</button>`;
    }

    function wireHandoffButton() {
        const btn = document.getElementById('__wg_handoff');
        if (btn) btn.addEventListener('click', () => window.open(btn.dataset.url, '_blank'));
    }

    function showBanner(isVuln, patterns, suspect, note, deepScanUrl, authorized) {
        removeBanner();

        banner = document.createElement('div');
        banner.id = '__webguard_banner';

        const patternNames = (patterns || []).map(p => p.type).join(' · ') || '';
        const verifyNote = 'This is an automated flag, not proof — verify manually before trusting it.';

        if (suspect && !isVuln) {
            // Amber — suspicious but unconfirmed
            banner.innerHTML = `
                <div style="display:flex;align-items:center;gap:12px;flex:1;">
                    <span style="font-size:18px;">🔎</span>
                    <div>
                        <strong style="font-size:13px;letter-spacing:.5px;">SUSPICIOUS — UNCONFIRMED</strong>
                        ${note ? `<div style="font-size:11px;opacity:.85;margin-top:2px;">${note.split('\n')[0]}</div>` : ''}
                        <div style="font-size:10px;opacity:.7;margin-top:2px;">${verifyNote}</div>
                    </div>
                </div>
                <div style="display:flex;gap:8px;align-items:center;">
                    ${handoffButtonHtml(deepScanUrl, authorized)}
                    <button id="__wg_close" style="background:rgba(255,255,255,.2);border:none;color:#fff;cursor:pointer;border-radius:4px;padding:4px 10px;font-size:12px;">✕</button>
                </div>`;
            Object.assign(banner.style, {
                position:'fixed', top:'0', left:'0', right:'0', zIndex:'2147483647',
                background:'linear-gradient(135deg,#b37700,#ffb020)',
                color:'#fff', padding:'12px 18px',
                display:'flex', alignItems:'center', justifyContent:'space-between',
                fontFamily:'system-ui,sans-serif',
                boxShadow:'0 4px 20px rgba(255,176,32,.5)',
            });
            setTimeout(removeBanner, 8000);
            document.body.appendChild(banner);
            document.getElementById('__wg_close')?.addEventListener('click', removeBanner);
            wireHandoffButton();
            return;
        }

        if (isVuln) {
            banner.innerHTML = `
                <div style="display:flex;align-items:center;gap:12px;flex:1;">
                    <span style="font-size:18px;">🚨</span>
                    <div>
                        <strong style="font-size:13px;letter-spacing:.5px;">VULNERABILITY DETECTED</strong>
                        ${patternNames ? `<div style="font-size:11px;opacity:.85;margin-top:2px;">${patternNames}</div>` : ''}
                        <div style="font-size:10px;opacity:.7;margin-top:2px;">${verifyNote}</div>
                    </div>
                </div>
                <div style="display:flex;gap:8px;align-items:center;">
                    ${handoffButtonHtml(deepScanUrl, authorized)}
                    <button id="__wg_close" style="background:rgba(255,255,255,.2);border:none;color:#fff;cursor:pointer;border-radius:4px;padding:4px 10px;font-size:12px;">✕</button>
                </div>`;
            Object.assign(banner.style, {
                position:   'fixed',
                top:        '0',
                left:       '0',
                right:      '0',
                zIndex:     '2147483647',
                background: 'linear-gradient(135deg,#ff3b5c,#c0002a)',
                color:      '#fff',
                padding:    '12px 18px',
                display:    'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                fontFamily: 'system-ui,sans-serif',
                boxShadow:  '0 4px 20px rgba(255,59,92,.5)',
                animation:  '__wg_slide .3s ease',
            });
        } else {
            // NOT a safety verdict. Passive monitoring cannot certify a site
            // as secure — it can only report that nothing surfaced while you
            // browsed. Neutral styling and wording, so it never reads as a
            // green "this site is safe" stamp it can't back up.
            banner.innerHTML = `
                <span style="font-size:14px;opacity:.8;">👁</span>
                <span style="font-size:12px;margin-left:10px;">WebGuard: watching — nothing flagged yet (not a scan)</span>
                <button id="__wg_close" style="background:rgba(255,255,255,.15);border:none;color:#fff;cursor:pointer;border-radius:4px;padding:3px 8px;font-size:11px;margin-left:auto;">✕</button>`;
            Object.assign(banner.style, {
                position:   'fixed',
                bottom:     '20px',
                right:      '20px',
                zIndex:     '2147483647',
                background: '#4a4f57',
                color:      '#fff',
                padding:    '10px 16px',
                borderRadius: '8px',
                display:    'flex',
                alignItems: 'center',
                fontFamily: 'system-ui,sans-serif',
                boxShadow:  '0 4px 16px rgba(0,0,0,.25)',
                fontSize:   '13px',
                maxWidth:   '340px',
            });
            // Auto-dismiss safe banner after 3s
            setTimeout(removeBanner, 3000);
        }

        // Inject keyframe animation once
        if (!document.getElementById('__wg_style')) {
            const style = document.createElement('style');
            style.id = '__wg_style';
            style.textContent = `
                @keyframes __wg_slide {
                    from { transform: translateY(-100%); opacity:0; }
                    to   { transform: translateY(0);     opacity:1; }
                }`;
            document.head.appendChild(style);
        }

        document.body.appendChild(banner);
        document.getElementById('__wg_close')?.addEventListener('click', removeBanner);
        wireHandoffButton();
    }

    // Listen for banner instructions from background.js
    chrome.runtime.onMessage.addListener((msg) => {
        if (msg.type === 'SHOW_BANNER') {
            showBanner(msg.vuln, msg.patterns, msg.suspect, msg.note, msg.deepScanUrl, msg.authorized);
        }
    });

})();
