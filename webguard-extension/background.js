// background.js  —  WebGuard Service Worker
// Context-aware vulnerability scanner.
// Never flags on a single signal alone — requires multiple co-occurring
// signals weighted by parameter context.

const BACKEND     = 'http://127.0.0.1:5000';
const COOLDOWN_MS = 4000;
const recentScans = new Map();

// ── PARAMETER CONTEXT ────────────────────────────────────────
// Low-risk: search/display fields — expected to contain weird chars
const LOW_RISK_PARAMS = new Set([
    'q','query','search','s','term','keyword','keywords',
    'text','message','comment','body','content','note',
    'description','title','name','username','email',
    'page','limit','offset','sort','order','filter',
    'lang','locale','format','type','category','tag',
    // NOTE: 'id' intentionally NOT here — it is the single most common SQLi
    // injection point, so a SQL keyword in `id` is anomalous, not benign.
    'ref','source','medium','campaign',
    'utm_source','utm_medium','utm_campaign','utm_term','utm_content',
    'gs_lcrp','oq','aqs','sourceid','ie','ved','ei','sa','rlz',
]);

// High-risk: execution/redirect fields — payload here is a real flag
const HIGH_RISK_PARAMS = new Set([
    'redirect','redirect_uri','redirect_url','return','return_to',
    'returnto','next','next_url','url','callback','goto',
    'dest','destination','target','file','path','filepath',
    'dir','folder','include','load','template','view','document',
    'cmd','command','exec','execute','run','shell',
    'sql','stmt','statement','data','payload','input','code','script',
    'token','api_key','apikey','key','secret',
]);

// ── ATTACK SIGNALS ───────────────────────────────────────────
const SIGNALS = [
    {
        name: 'sql_keywords',
        test: v => /(\bor\b|\band\b)\s+['"\d]|union\s+(all\s+)?select|;\s*drop\s+table|sleep\s*\(\d|benchmark\s*\(|'\s*--|\bxp_cmdshell\b|information_schema/i.test(v),
        score: 2,
    },
    {
        name: 'xss_tags',
        test: v => /<\s*script[\s>]|javascript\s*:|on(load|error|click|mouseover|focus)\s*=|<\s*iframe|<\s*img[^>]+onerror|document\.(cookie|location)|vbscript\s*:/i.test(v),
        score: 2,
    },
    {
        name: 'path_traversal',
        test: v => /(\.\.[/\\]){2,}|%2e%2e%2f|\/etc\/(passwd|shadow)|c:\\windows/i.test(v),
        score: 2,
    },
    {
        name: 'command_injection',
        test: v => /;\s*(ls|cat|id|whoami|wget|curl|bash|sh)\b|\|\s*(ls|cat|id|bash)|\$\([^)]+\)|`[^`]+(ls|cat|id)[^`]*`/i.test(v),
        score: 2,
    },
    {
        name: 'heavy_url_encoding',
        // Only suspicious in context — weak signal alone
        test: v => (v.match(/%[0-9a-f]{2}/gi) || []).length >= 5,
        score: 1,
    },
    {
        name: 'html_entities',
        test: v => /(&lt;|&gt;|&quot;|&#x?[0-9a-f]+;)/i.test(v),
        score: 1,
    },
    {
        name: 'base64_with_keyword',
        test(v) {
            if (!/^[A-Za-z0-9+/]{20,}={0,2}$/.test(v)) return false;
            try {
                const d = atob(v);
                return /script|passwd|select|union|exec|eval/i.test(d);
            } catch { return false; }
        },
        score: 2,
    },
    {
        name: 'double_encoding',
        test: v => /%25[0-9a-f]{2}|%252e|%253c|%253e/i.test(v),
        score: 2,
    },
    {
        name: 'ssrf_internal',
        test: v => /https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.|192\.168\.|10\.\d|172\.(1[6-9]|2\d|3[01])\.)|file:\/\/|gopher:\/\//i.test(v),
        score: 3,
    },
];

// Signals strong enough to be worth a look on their own (score >= 2).
// Weak signals (heavy_url_encoding, html_entities) only count as corroboration.
const STRONG_SIGNALS = new Set(SIGNALS.filter(s => s.score >= 2).map(s => s.name));

// ── CONTEXT-AWARE SCORER ─────────────────────────────────────

function scoreParam(paramName, paramValue) {
    const name  = (paramName  || '').toLowerCase();
    const value = (paramValue || '').trim();
    if (!value || value.length < 3) return { score: 0, signals: [] };

    const fired = SIGNALS.filter(s => s.test(value));
    if (fired.length === 0) return { score: 0, signals: [] };

    let score = fired.reduce((a, s) => a + s.score, 0);

    // Context multiplier
    const multiplier = HIGH_RISK_PARAMS.has(name) ? 1.5
                     : LOW_RISK_PARAMS.has(name)  ? 0.4
                     : 1.0;
    score = Math.round(score * multiplier * 10) / 10;

    return {
        score,
        signals: fired.map(s => s.name),
        param:   name,
        value:   value.slice(0, 80),
        context: HIGH_RISK_PARAMS.has(name) ? 'high-risk'
               : LOW_RISK_PARAMS.has(name)  ? 'low-risk'
               : 'neutral',
    };
}

function analyseURL(rawUrl) {
    let url;
    try { url = new URL(rawUrl); } catch { return null; }

    const results = [];
    for (const [key, val] of url.searchParams.entries()) {
        const r = scoreParam(key, val);
        if (r.score > 0) results.push(r);
    }

    // Also check path
    const pathR = scoreParam('path', url.pathname);
    if (pathR.score > 0) results.push(pathR);

    if (!results.length) return null;

    const totalScore   = results.reduce((a, r) => a + r.score, 0);
    const totalSignals = [...new Set(results.flatMap(r => r.signals))];

    // A "strong" signal is one worth a closer look on its own (sql/xss/
    // traversal/cmdi/ssrf/etc). Weak signals (encoding, entities) never flag
    // alone. Returning non-null here does NOT mean "vulnerable" — it means
    // "worth checking"; the red vs amber decision is made downstream.
    const hasStrong = results.some(r => r.signals.some(n => STRONG_SIGNALS.has(n)));

    // Flag when: multiple co-occurring signals, one very high score, OR a
    // single strong signal that survived context weighting (>=2). The last
    // clause is what routes a lone real signal to AMBER instead of silence.
    const shouldFlag = (totalScore >= 3 && totalSignals.length >= 2)
                     || totalScore >= 4
                     || (hasStrong && totalScore >= 2);
    if (!shouldFlag) return null;

    return { totalScore, signals: totalSignals, params: results };
}

function buildNote(analysis) {
    if (!analysis) return '';
    return analysis.params.map(p => {
        const ctx = p.context === 'high-risk' ? '⚠ dangerous field'
                  : p.context === 'low-risk'  ? 'likely benign'
                  : 'investigate';
        return `${p.param}= [${p.signals.join('+')}] — ${ctx}`;
    }).join('\n');
}

// ── BADGE ─────────────────────────────────────────────────────

function setBadge(state) {
    const map = {
        vuln:     ['!', '#ff3b5c'],
        suspect:  ['?', '#ffb020'],
        // Neutral grey, not green — "nothing flagged" is not a safety verdict.
        safe:     ['·', '#9aa0a6'],
        scanning: ['…', '#00e5ff'],
        login:    ['🔒', '#a855f7'],
        clear:    ['' , '#888888'],
    };
    const [text, color] = map[state] || map.clear;
    chrome.action.setBadgeText({ text });
    chrome.action.setBadgeBackgroundColor({ color });
}

// ── AUTHORIZATION CHECK ──────────────────────────────────────
// WebGuard the app only ever sends real payloads at hosts on the analyst's
// authorized-targets allowlist. The extension never fires payloads itself —
// it only uses this to decide which handoff button/label to show.

async function isAuthorized(pageUrl) {
    if (!pageUrl) return false;
    try {
        const host = new URL(pageUrl).host.toLowerCase();
        const r = await fetch(`${BACKEND}/api/targets`, {
            credentials: 'include',
            signal: AbortSignal.timeout(3000),
        });
        if (!r.ok) return false; // not logged in / backend down — default to "not authorized"
        const targets = await r.json();
        return targets.some(t => (t.netloc || '').toLowerCase() === host);
    } catch {
        return false;
    }
}

// ── CORE SCAN ────────────────────────────────────────────────

async function scanInput(input, source, tabId, pageUrl) {
    const now = Date.now();
    if ((recentScans.get(input) || 0) + COOLDOWN_MS > now) return;
    recentScans.set(input, now);
    if (recentScans.size > 200) {
        [...recentScans.entries()].sort((a,b)=>a[1]-b[1]).slice(0,100)
            .forEach(([k]) => recentScans.delete(k));
    }

    setBadge('scanning');

    // ── Local URL analysis — fast, no network ──
    let localAnalysis = null;
    if (source === 'URL navigation') {
        localAnalysis = analyseURL(input);

        if (!localAnalysis) {
            // Locally clean — skip backend, mark safe immediately
            setBadge('safe');
            chrome.tabs.sendMessage(tabId, { type:'SHOW_BANNER', vuln:false }).catch(()=>{});
            const record = {
                input:input.slice(0,300), source, tabId, timestamp:Date.now(),
                backendUp:true,
                scanResult:{ vulnerable:false, confidence:0.95, patterns:[], ml_label:'SAFE' },
                aiResult:null,
            };
            chrome.storage.local.get({history:[]}, d =>
                chrome.storage.local.set({ lastScan:record, history:[record,...d.history].slice(0,50) })
            );
            return;
        }
    }

    // ── Backend call ──
    let scanResult = null;
    let aiResult   = null;
    let backendUp  = true;

    try {
        const r = await fetch(`${BACKEND}/api/analyze`, {
            method: 'POST',
            headers: { 'Content-Type':'application/json' },
            body: JSON.stringify({ code: input }),
            credentials: 'include',
            // Generous: the backend may still be loading the ML model on first use.
            signal: AbortSignal.timeout(30000),
        });

        if (r.status === 401) {
            // The session cookie belongs to the exact host the dashboard was opened on,
            // so logging in at 127.0.0.1:5000 does not log in localhost:5000.
            console.warn(`WebGuard: Unauthorized. Please log in to the dashboard at ${BACKEND}`);
            setBadge('login');
            chrome.action.setTitle({ title: `WebGuard — log in at ${BACKEND} to enable scanning` });
            return;
        }
        chrome.action.setTitle({ title: 'WebGuard' });

        scanResult = await r.json();

        // For URLs: only flag if local analysis AND backend BOTH agree
        if (source === 'URL navigation' && localAnalysis && !scanResult.vulnerable) {
            scanResult._suspect   = true;
            scanResult._localNote = buildNote(localAnalysis);
        }

        // AI explanation
        try {
            const ar = await fetch(`${BACKEND}/api/explain`, {
                method: 'POST',
                headers: { 'Content-Type':'application/json' },
                body: JSON.stringify({ scan_result:scanResult, input_text:input }),
                credentials: 'include',
                signal: AbortSignal.timeout(10000),
            });
            if (ar.status === 401) {
                console.warn('WebGuard AI: Unauthorized.');
            } else {
                const ad = await ar.json();
                const raw = ad.result;
                aiResult = raw && typeof raw === 'object' ? raw
                    : (() => { try { return JSON.parse((raw||'').replace(/```json|```/g,'').trim()); } catch { return null; } })();
            }
        } catch(e) { console.warn('WebGuard AI:', e.message); }

    } catch(err) {
        console.warn('WebGuard backend unreachable:', err.message);
        backendUp = false;
    }

    const record = {
        input:input.slice(0,300), source, tabId, timestamp:Date.now(),
        backendUp, scanResult, aiResult, localAnalysis,
    };
    chrome.storage.local.get({history:[]}, d =>
        chrome.storage.local.set({ lastScan:record, history:[record,...d.history].slice(0,50) })
    );

    if (!backendUp) { setBadge('clear'); return; }

    const isVuln    = scanResult?.vulnerable;
    const isSuspect = scanResult?._suspect || scanResult?.needs_review;

    if (isVuln || isSuspect) {
        // Only the app is ever allowed to fire real payloads at a target, and
        // only once that host is on the authorized-targets allowlist. This
        // just decides which handoff button/label to offer.
        const authorized = await isAuthorized(pageUrl);
        const deepScanUrl = pageUrl || input;

        if (isVuln) {
            setBadge('vuln');
            const pts = (scanResult.patterns||[]).map(p=>p.type).join(', ');
            chrome.notifications.create({
                type:'basic', iconUrl:'icons/icon48.png',
                title:'🚨 WebGuard — Vulnerability Detected',
                message:`${pts||'Suspicious input'} — click extension for details`,
                priority:2,
            });
            chrome.tabs.sendMessage(tabId, {
                type:'SHOW_BANNER', vuln:true, patterns:scanResult.patterns||[], deepScanUrl, authorized,
            }).catch(()=>{});
        } else {
            setBadge('suspect');
            chrome.tabs.sendMessage(tabId, {
                type:'SHOW_BANNER', vuln:false, suspect:true, note:scanResult._localNote, deepScanUrl, authorized,
            }).catch(()=>{});
        }

    } else {
        setBadge('safe');
        chrome.tabs.sendMessage(tabId, { type:'SHOW_BANNER', vuln:false }).catch(()=>{});
    }
}

// ── PASSIVE RESPONSE-BODY EVIDENCE ───────────────────────────
// content.js matched a high-confidence leak signature (a DB error, stack
// trace, leaked /etc/passwd, ...) in text the page ALREADY rendered. This is
// direct evidence, not a probe, so it goes straight to the red banner. No
// payload was sent and the page content was not transmitted — only the
// signature names arrive here.

async function showPageEvidence(patterns, tabId, pageUrl) {
    const pats = [...new Set(patterns || [])].map(type => ({ type }));
    if (!pats.length) return;

    setBadge('vuln');

    const record = {
        input: (pageUrl || '').slice(0, 300), source: 'Response body', tabId, timestamp: Date.now(),
        backendUp: true,
        scanResult: { vulnerable: true, confidence: 0.98, patterns: pats, ml_label: 'VULNERABLE' },
        aiResult: null,
    };
    chrome.storage.local.get({ history: [] }, d =>
        chrome.storage.local.set({ lastScan: record, history: [record, ...d.history].slice(0, 50) })
    );

    chrome.notifications.create({
        type: 'basic', iconUrl: 'icons/icon48.png',
        title: '🚨 WebGuard — Vulnerability Evidence on Page',
        message: `${pats.map(p => p.type).join(', ')} — visible in the page's response`,
        priority: 2,
    });

    const authorized = await isAuthorized(pageUrl);
    chrome.tabs.sendMessage(tabId, {
        type: 'SHOW_BANNER', vuln: true, patterns: pats, deepScanUrl: pageUrl, authorized,
    }).catch(() => {});
}

// ── MESSAGES FROM content.js ─────────────────────────────────

chrome.runtime.onMessage.addListener((msg, sender) => {
    const tabId = sender.tab?.id;
    if (!tabId) return;
    if (msg.type === 'SCAN_INPUT')    scanInput(msg.input, msg.source, tabId, msg.pageUrl);
    if (msg.type === 'SCAN_URL')      scanInput(msg.url, 'URL navigation', tabId, msg.url);
    if (msg.type === 'PAGE_EVIDENCE') showPageEvidence(msg.patterns, tabId, msg.pageUrl);
});

// ── URL NAVIGATION ────────────────────────────────────────────

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
        if (tab.url.startsWith('chrome://') ||
            tab.url.startsWith('chrome-extension://') ||
            tab.url === 'about:blank') return;
        scanInput(tab.url, 'URL navigation', tabId, tab.url);
    }
});
