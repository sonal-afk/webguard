# ============================================================
# backend.py  —  WebGuard Flask API
# Fixed pattern detection for web vulnerability scanning
# ============================================================

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3
import re
import os
import logging
import secrets
import hashlib
import ipaddress
import socket
import time
import threading
import uuid
from pathlib import Path
from contextlib import contextmanager
from functools import wraps
from urllib.parse import urlparse, unquote
import json
import html

BASE_DIR = Path(__file__).resolve().parent
DATABASE_DIR = BASE_DIR / "database"
DATABASE_PATH = DATABASE_DIR / "vulnerabilities.db"
_MODEL_OVERRIDE = os.getenv('WEBGUARD_MODEL_PATH')
MODEL_CANDIDATES = ([Path(_MODEL_OVERRIDE)] if _MODEL_OVERRIDE else []) + \
                   [BASE_DIR / "web_vuln_model", BASE_DIR / "my_vuln_model"]
LOG_PATH = BASE_DIR / "webguard.log"

# ── Environment variables ─────────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed — use system env vars

DEBUG = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
PORT  = int(os.getenv('PORT', 5000))
HOST  = os.getenv('HOST', '127.0.0.1')

# ── Logging ───────────────────────────────────────────────────
logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.FileHandler(LOG_PATH, encoding='utf-8'),
        logging.StreamHandler(),
    ]
)
logger = logging.getLogger('webguard')

app = Flask(__name__)
CORS(app, supports_credentials=True)

# ── Rate Limiting ─────────────────────────────────────────────
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri='memory://',
)

# ── Server-Side Authentication ────────────────────────────────
ADMIN_USERNAME    = os.getenv('ADMIN_USER', 'admin')
ADMIN_PASSWORD_HASH = hashlib.sha256(
    os.getenv('ADMIN_PASSWORD', 'admin123').encode()
).hexdigest()
SESSIONS = {}  # token -> True

def require_auth(f):
    """Decorator: reject requests without a valid session cookie."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('wg_session')
        if not token or token not in SESSIONS:
            return jsonify({'error': 'Unauthorized — please log in'}), 401
        return f(*args, **kwargs)
    return decorated

DATABASE_DIR.mkdir(exist_ok=True)
(BASE_DIR / "templates").mkdir(exist_ok=True)
(BASE_DIR / "static").mkdir(exist_ok=True)

# ── Load ML model ─────────────────────────────────────────────
MODEL_PATH = next((path for path in MODEL_CANDIDATES if path.exists()), None)
vulnerability_detector = None
model_load_error = None
_model_lock = threading.Lock()


def get_vulnerability_detector():
    global vulnerability_detector, model_load_error

    if vulnerability_detector is not None or model_load_error is not None:
        return vulnerability_detector

    # Startup preload and the first request can race; load only once.
    with _model_lock:
        return _load_vulnerability_detector()


def _load_vulnerability_detector():
    global vulnerability_detector, model_load_error

    if vulnerability_detector is not None or model_load_error is not None:
        return vulnerability_detector

    if MODEL_PATH is None:
        model_load_error = "No local ML model directory found"
        logger.warning("%s; using pattern-only detection", model_load_error)
        return None

    try:
        import torch
        from transformers import pipeline

        logger.info("Loading ML model from %s...", MODEL_PATH)
        vulnerability_detector = pipeline(
            "text-classification",
            model=str(MODEL_PATH),
            tokenizer=str(MODEL_PATH),
            device=0 if torch.cuda.is_available() else -1,
        )
        logger.info("Model loaded")
    except Exception as exc:
        model_load_error = str(exc)
        logger.exception("Could not load ML model; using pattern-only detection")

    return vulnerability_detector

# ============================================================
# DATABASE
# ============================================================

def init_database():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL,
            vulnerable INTEGER NOT NULL,
            cwe TEXT, description TEXT, severity TEXT,
            language TEXT, source TEXT, project TEXT
        ) 
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS detection_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL,
            predicted_vulnerable INTEGER,
            confidence REAL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS authorized_targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            netloc TEXT NOT NULL UNIQUE,
            note TEXT,
            added_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()
    logger.info("Database initialized")

@contextmanager
def get_db():
    """Context manager: auto-commits on success, rolls back on error, always closes."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def get_vuln_count():
    with get_db() as conn:
        return conn.execute('SELECT COUNT(*) as c FROM vulnerabilities').fetchone()['c']

def search_similar(code, limit=3, cwes=None):
    with get_db() as conn:
        # Prefer records with the same weakness the pattern engine found; a
        # keyword match alone pulls unrelated C code (e.g. 'select' in a
        # buffer-overflow function) for a web SQL injection.
        if cwes:
            results = conn.execute(
                f'''SELECT * FROM vulnerabilities WHERE vulnerable=1
                    AND cwe IN ({','.join('?' for _ in cwes)}) ORDER BY RANDOM() LIMIT ?''',
                list(cwes) + [limit]
            ).fetchall()
            if results:
                return [dict(r) for r in results]
        keywords = ['strcpy','system','eval','exec','SELECT','innerHTML',
                    'sprintf','script','passwd','union','sleep']
        found = [kw for kw in keywords if kw.lower() in code.lower()]
        if found:
            query = f'''SELECT * FROM vulnerabilities WHERE vulnerable=1
                        AND ({' OR '.join(['code LIKE ?' for _ in found])}) LIMIT ?'''
            results = conn.execute(query, [f'%{kw}%' for kw in found]+[limit]).fetchall()
        else:
            results = conn.execute(
                'SELECT * FROM vulnerabilities WHERE vulnerable=1 ORDER BY RANDOM() LIMIT ?',
                (limit,)
            ).fetchall()
        return [dict(r) for r in results]

# ============================================================
# WEB ATTACK PATTERN DETECTION  (fixed)
# ============================================================

# Mitigations — evidence that a snippet of CODE defends against one specific
# category. Each one only cancels findings of its own category (a prepared
# statement says nothing about XSS), and they all require call syntax, so
# typing the word "parameterized" into a URL cannot switch detection off.
MITIGATIONS = {
    'SQL Injection': [
        r'\.prepare(statement)?\s*\(',
        r'pdo::\s*prepare',
        r'mysqli_real_escape_string\s*\(',
        r'\.execute\s*\(\s*["\'][^"\']*(%s|\?|:\w+)[^"\']*["\']\s*,',   # cursor.execute("... %s", (x,))
    ],
    'XSS': [
        r'htmlspecialchars\s*\(',
        r'htmlentities\s*\(',
        r'bleach\.clean\s*\(',
        r'dompurify\.sanitize\s*\(',
        r'markupsafe\.escape\s*\(',
        r'\.textcontent\s*=',
    ],
}

# Kept for callers that only need a yes/no "does this code use a known
# mitigation" answer (e.g. the dashboard's SAFE_PATTERN label).
SAFE_PATTERNS = [p for pats in MITIGATIONS.values() for p in pats]


def has_safe_pattern(code):
    """True if the code contains at least one recognised mitigation."""
    code_lower = code.lower()
    return any(re.search(p, code_lower) for p in SAFE_PATTERNS)


def _mitigated_categories(code):
    code_lower = code.lower()
    return {cat for cat, pats in MITIGATIONS.items()
            if any(re.search(p, code_lower) for p in pats)}


# Building blocks shared by several rules.
# PARAM_VALUE: the start of a query-string / form value ("?id=", "&q=", or a
# body line "data=") — rules anchored on it only fire on user-supplied input,
# not on ordinary code that happens to contain the same characters.
PARAM_VALUE = r'(?:^|[?&\n;])[\w.\[\]-]+='
SHELL_CMDS = (r'(?:echo|ping|sleep|nslookup|dig|host|curl|wget|nc|ncat|netcat|bash|sh|zsh|'
              r'powershell|cmd|python3?|perl|ruby|php|rm|ls|cat|id|whoami|uname|pwd|type|'
              r'dir|net|ifconfig|ipconfig|hostname|timeout|touch|chmod|head|tail|more)')
INTERNAL_HOST = (r'(?:localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|0x7f[0-9a-f]*|'
                 r'2130706433|\[(?:0*:)*:?0*1?\]|169\.254\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
                 r'192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|'
                 r'metadata\.google\.internal|[\w.-]+\.internal)')
REDIRECT_PARAMS = (r'(?:redirect|redirect_?ur[il]|redir|next|url|return|return_?to|return_?url|'
                   r'returnurl|goto|dest|destination|continue|callback|forward|target|to|out|'
                   r'login_?url|success_?url|r|u)')


WEB_PATTERNS = {
    # ── SQL Injection ──────────────────────────────────────
    'SQL Injection': {
        'patterns': [
            r"'\s*\)*\s*(or|and)\s+['\"0-9a-z(]",        # ' OR '1'='1, ') AND (
            r"\b(or|and)\s+\d+\s*(=|<|>|<>|!=)\s*\d+",   # OR 1=1, AND 2>1
            r"union\s+(all\s+)?select",                  # UNION SELECT
            r";\s*(drop|delete|insert|update|alter|create|exec|shutdown)\s",  # stacked query
            r"['\")]\s*(--|#)(?=\s|$|&|-)",              # admin'--, ')-- , '#  (not jQuery '#id')
            r"order\s+by\s+\d+\s*(--|#)",                # column-count probe
            r"\b(and|or|select|;|\))\s*\(?\s*(sleep|pg_sleep)\s*\(\s*\d+",   # time-based
            r"benchmark\s*\(\s*\d+\s*,",                 # BENCHMARK(1000000,
            r"waitfor\s+delay",                          # WAITFOR DELAY
            r"'\s*;\s*select",                           # '; SELECT
            r"xp_cmdshell",
            r"information_schema",
            r"\b(extractvalue|updatexml|load_file)\s*\(",
            r"into\s+(out|dump)file",
            r"(select|union|where|concat|char)\b[^\n]{0,60}0x[0-9a-f]{4,}",  # hex-encoded strings
            # A value that is just a number (or nothing) followed by a quote:
            # id=1'  q='  id=12" — the classic "does it break the query?" probe.
            # The quote must END the value, so a quote inside a word or phrase
            # (q=O'Brien, q=don't, q=5' 10" height) does NOT match.
            PARAM_VALUE + r"\d*['\"](?=$|[&#\n]|\s+http/)",
        ],
        'cwe': 'CWE-89',
        'severity': 'CRITICAL',
    },

    # ── Cross-Site Scripting ───────────────────────────────
    'XSS': {
        'patterns': [
            r'<\s*script[^>]*>',                         # <script>
            r'(javascript|vbscript)\s*:',                # javascript:
            r'<[a-z][^>]*\bon[a-z]{3,}\s*=',             # <img onerror=  <details ontoggle=
            r'[\'"]\s*\bon[a-z]{3,}\s*=',                # " onmouseover=  (attribute breakout)
            r'[\'"]\s*>\s*<\s*[a-z]',                    # "><svg  (tag breakout)
            r'document\s*\.\s*cookie',
            r'(innerhtml|outerhtml)\s*=[^;\n]*(location|document\.url|\.hash|\.search|\.referrer)',
            r'document\s*\.\s*write(ln)?\s*\([^)]*(location|\.hash|\.search|\.referrer)',
            r'<\s*iframe[^>]*>',
            r'expression\s*\(',                          # CSS expression()
            r'data\s*:\s*text/html',
            r'\bsrcdoc\s*=',
            # Any HTML tag inside a query/form value: q=<b>  bio=<i>hi</i>
            PARAM_VALUE + r'[^&\s]*<\s*/?\s*[a-z][a-z0-9]*[\s>/]',
        ],
        'cwe': 'CWE-79',
        'severity': 'HIGH',
    },

    # ── Path / Directory Traversal ─────────────────────────
    'Path Traversal': {
        'patterns': [
            r'\.\.[/\\]',                                # ../  ..\
            r'\.\.\.\.//',                               # ....// filter bypass
            r'%c0%ae|%c1%9c',                            # overlong UTF-8 dot / slash
            r'/etc/(passwd|shadow|hosts|group)',
            r'/proc/self/(environ|cmdline|fd)',
            r'c:\\+windows',
            r'boot\.ini',
            r'win\.ini',
            PARAM_VALUE + r'(file|php|zip|phar|expect)://',   # include wrappers
        ],
        'cwe': 'CWE-22',
        'severity': 'HIGH',
    },

    # ── Command Injection ──────────────────────────────────
    'Command Injection': {
        'patterns': [
            # A shell separator inside a parameter value followed by a command:
            # host=8.8.8.8;id   q=|echo x   ip=1.1.1.1 && type   x=%0Asleep 5
            # (?!\s*:) skips HTTP header lines such as "Host: ..." after a request line.
            PARAM_VALUE + r'[^&\n]*?(?:[;|\n]|&&)\s*(?:/(?:usr/)?bin/)?' + SHELL_CMDS + r'\b(?!\s*:)',
            PARAM_VALUE + r'&&\s*' + SHELL_CMDS + r'\b',       # id=&&echo (raw & splits params)
            r'(?:[;|]|&&)\s*(?:cat|type|more)\s+\S*(passwd|shadow|win\.ini|hosts)',
            r';\s*(?:/(?:usr/)?bin/)?(ls|cat|pwd|whoami|id|uname|wget|curl|bash|sh|nc|netcat)\b(?!\s*=)',
            r'\|\s*(whoami|id|bash|sh|nc)\b(?!\s*=)',
            r'`[^`]*\b' + SHELL_CMDS + r'\b[^`]*`',           # `nslookup x`
            r'\$\(\s*' + SHELL_CMDS + r'\b',                  # $(whoami) — not jQuery $('#id')
            # Dangerous sinks in pasted code
            r'(?<![\w.])(system|shell_exec|passthru|proc_open|popen)\s*\(',
            r'os\.(system|popen)\s*\(',
            r'subprocess\.\w+\([^)]*shell\s*=\s*true',
            r'runtime\.getruntime\(\)\.exec\s*\(',
            r'child_process[^\n]*\bexec\s*\(',
        ],
        'cwe': 'CWE-78',
        'severity': 'CRITICAL',
    },

    # ── SSRF ──────────────────────────────────────────────
    'SSRF': {
        'patterns': [
            # Any parameter whose value points at an internal / cloud-metadata address
            PARAM_VALUE + r'\s*(https?|ftp)://' + INTERNAL_HOST + r'(?=[:/?#&\s]|$)',
            PARAM_VALUE + r'\s*' + INTERNAL_HOST + r':\d{2,5}',
            r'(gopher|dict|ldap|tftp)://',
            r'file:///',
            r'/latest/meta-data|/computemetadata/v1',
        ],
        'cwe': 'CWE-918',
        'severity': 'HIGH',
    },

    # ── Open Redirect ─────────────────────────────────────
    # Literal patterns cover the tricks that are almost never legitimate
    # (protocol-relative //evil, /\evil, \\evil in any parameter). Absolute
    # URLs in a redirect-style parameter are handled by
    # _external_redirect_targets(), which compares the target's host with the
    # host of the pasted URL / request so same-site redirects are not flagged.
    'Open Redirect': {
        'patterns': [
            PARAM_VALUE + r'\s*(//|/\\|\\\\)[\w-]+\.[\w.-]+',
        ],
        'cwe': 'CWE-601',
        'severity': 'MEDIUM',
    },

    # ── XXE ───────────────────────────────────────────────
    'XXE': {
        'patterns': [
            r'<!entity',
            r'<!doctype[^>]+system',
            r'system\s+"(file|http|ftp|php|expect)',
            r'&xxe;',
        ],
        'cwe': 'CWE-611',
        'severity': 'HIGH',
    },

    # ── SSTI ──────────────────────────────────────────────
    # Ordinary templates ({{ user.name }}, {% for %}, `${count}`) are not
    # attacks. These rules look for probe arithmetic, Python/Java internals,
    # or template syntax arriving inside a URL/form value.
    'SSTI': {
        'patterns': [
            r'(\{\{|\$\{|#\{|\{%|\{#)\s*\d+\s*[*+]\s*\d+',      # {{7*7}} ${7*7}
            r'\{\{[^}]*(__class__|__mro__|__subclasses__|__globals__|__builtins__|__import__|'
            r'config\.|self\.|request\.application|lipsum|cycler|joiner|popen)',
            r'\$\{[^}]*(runtime|getclass|java\.lang|t\(java|exec\()',
            r'<#assign|freemarker\.template\.utility',
            PARAM_VALUE + r'[^&\s]*(\{\{|\{%|\$\{|#\{)',            # template syntax in a value
        ],
        'cwe': 'CWE-94',
        'severity': 'HIGH',
    },

    # ── Hardcoded Credentials ─────────────────────────────
    'Hardcoded Credentials': {
        'patterns': [
            r'(password|passwd|pwd|secret|api_?key|apikey|token|access_?key)\w*\s*[:=]\s*["\'][^"\'\s]{4,}["\']',
            r'\bakia[0-9a-z]{16}\b',                               # AWS access key id
            r'-----begin (rsa |ec |dsa |openssh )?private key-----',
            r'\bgh[pousr]_[a-z0-9]{36}\b',                         # GitHub token
            r'\baiza[0-9a-z_\-]{35}\b',                            # Google API key
            r'\bxox[baprs]-[a-z0-9-]{10,}',                        # Slack token
        ],
        'cwe': 'CWE-798',
        'severity': 'HIGH',
    },
}

_REDIRECT_VALUE_RE = re.compile(
    r'(?:^|[?&\n;])' + REDIRECT_PARAMS + r'=\s*(https?:)?//([^/?#&\s\\]+)', re.IGNORECASE)


def _own_host(text):
    """Host of the pasted URL or HTTP request itself, if it has one."""
    m = re.match(r'\s*https?://([^/?#\s]+)', text, re.IGNORECASE)
    if not m:
        m = re.search(r'^host:\s*([^\s]+)', text, re.IGNORECASE | re.MULTILINE)
    if not m:
        return None
    return m.group(1).rsplit('@', 1)[-1].split(':')[0].lower()


def _same_site(a, b):
    """True if two hosts share a registrable domain (www.acme.io ~ login.acme.io)."""
    def base(h):
        parts = h.split('.')
        # handle two-part public suffixes such as co.uk / ac.in / com.au
        if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in ('co', 'ac', 'com', 'org', 'gov', 'net', 'edu'):
            return '.'.join(parts[-3:])
        return '.'.join(parts[-2:])
    return base(a) == base(b)


def _external_redirect_targets(texts, original):
    """Yield True if a redirect-style parameter points at a different site."""
    own = _own_host(original)
    for text in texts:
        for m in _REDIRECT_VALUE_RE.finditer(text):
            target = m.group(2).rsplit('@', 1)[-1].split(':')[0].lower()
            if own is None or not _same_site(own, target):
                return True
    return False


def _normalised_variants(code):
    """Forms of the input the rules are checked against.

    Attackers hide payloads with URL encoding (once or twice), HTML entities,
    SQL inline comments (/**/) and odd spacing. Each normalisation only adds
    a variant to check, never removes the original, so it can only add
    matches.
    """
    variants = {code.lower()}
    text = code
    for _ in range(2):                          # %27 and double-encoded %2527
        try:
            decoded = unquote(text)
        except Exception:
            break
        if decoded == text:
            break
        variants.add(decoded.lower())
        text = decoded
    for v in list(variants):
        unescaped = html.unescape(v)
        if unescaped != v:
            variants.add(unescaped.lower())
    for v in list(variants):
        if '/*' in v:
            variants.add(re.sub(r'\s+', ' ', re.sub(r'/\*.*?\*/', ' ', v)))
    return variants


def detect_patterns(code):
    """Run all web attack pattern checks against input.

    Returns one finding per category. Findings for a category are dropped
    when the (code) input also shows a mitigation for that same category.
    """
    variants = _normalised_variants(code)
    mitigated = _mitigated_categories(code)
    findings = []

    for vuln_name, info in WEB_PATTERNS.items():
        if vuln_name in mitigated:
            continue
        matched = any(re.search(pattern, text, re.IGNORECASE)
                      for pattern in info['patterns'] for text in variants)
        if not matched and vuln_name == 'Open Redirect':
            matched = _external_redirect_targets(variants, code)
        if matched:
            findings.append({
                'type': vuln_name,
                'cwe':  info['cwe'],
                'severity': info['severity'],
            })

    return findings


# ============================================================
# ANALYSIS
# ============================================================

def analyze(code):
    # 1. Pattern-based detection (always runs and is fast)
    pattern_findings = detect_patterns(code)
    is_safe          = has_safe_pattern(code)

    # 2. Decision logic - Early exit for clear patterns. detect_patterns()
    # has already dropped any category the code visibly mitigates.
    if pattern_findings:
        return {
            'vulnerable':             True,
            'needs_review':           False,
            'verdict':                'VULNERABLE',
            'confidence':             0.95,
            'ml_score':               0.0,
            'ml_label':               'PATTERN_MATCH',
            'patterns':               pattern_findings,
            'safe_patterns':          False,
            'similar_vulnerabilities': search_similar(code, cwes={p['cwe'] for p in pattern_findings}),
        }

    if is_safe and not pattern_findings:
        return {
            'vulnerable':             False,
            'needs_review':           False,
            'verdict':                'SAFE',
            'confidence':             0.98,
            'ml_score':               0.0,
            'ml_label':               'SAFE_PATTERN',
            'patterns':               [],
            'safe_patterns':          True,
            'similar_vulnerabilities': [],
        }

    # 3. ML model detection (Slow fallback only for ambiguous cases)
    logger.info("Running ML inference (slow fallback)...")
    try:
        # Limit to 512 chars for performance
        detector = get_vulnerability_detector()
        if detector is None:
            raise RuntimeError(model_load_error or "ML model is unavailable")
        ml_result    = detector(code[:512])[0]
        ml_score     = ml_result['score']
        ml_label     = ml_result['label']
        ml_vulnerable = ml_label in ('INSECURE', 'LABEL_1', '1', 'VULNERABLE')
    except Exception as e:
        logger.error(f"ML error: {e}")
        ml_score     = 0.5
        ml_label     = 'PATTERN_ONLY'
        ml_vulnerable = False

    # The model alone never confirms a vulnerability. On realistic harmless
    # input (template literals, Jinja templates, "rock 'n' roll") it is wrong
    # with >99% confidence, so a confidence threshold cannot separate its
    # mistakes from its catches (see benchmark/realistic_set.py). A model-only
    # hit is therefore reported as NEEDS_REVIEW for a human or the active
    # scanner to confirm, not as VULNERABLE.
    needs_review = ml_vulnerable
    confidence   = ml_score
    similar = search_similar(code) if needs_review else []

    return {
        'vulnerable':             False,
        'needs_review':           needs_review,
        'verdict':                'NEEDS_REVIEW' if needs_review else 'SAFE',
        'confidence':             float(confidence),
        'ml_score':               float(ml_score),
        'ml_label':               ml_label,
        'patterns':               pattern_findings,
        'safe_patterns':          is_safe and not pattern_findings,
        'similar_vulnerabilities': similar,
    }


# ============================================================
# SSRF PROTECTION
# ============================================================

BLOCKED_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),       # Private Class A
    ipaddress.ip_network('172.16.0.0/12'),     # Private Class B
    ipaddress.ip_network('192.168.0.0/16'),    # Private Class C
    ipaddress.ip_network('169.254.0.0/16'),    # Link-local
]

def _is_blocked_ip(hostname):
    """True if hostname is a literal IP inside a blocked private/link-local range."""
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return any(ip in network for network in BLOCKED_NETWORKS)


def is_safe_url(url):
    """Validate a scan target URL. Blocks non-HTTP schemes and private IPs (except localhost).

    Also resolves hostnames via DNS and blocks them if they resolve to a
    private/link-local IP, to close the DNS-rebinding gap where a public
    domain name points at an internal address.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return False, 'Only http:// and https:// URLs are allowed'
        hostname = parsed.hostname
        if not hostname:
            return False, 'Invalid URL — no hostname found'

        if _is_blocked_ip(hostname):
            return False, f'Scanning private IP {hostname} is blocked (SSRF protection)'

        # If hostname is a domain name (not a literal IP or localhost), resolve
        # it and make sure it doesn't point at a private/internal address.
        if hostname != 'localhost':
            try:
                ipaddress.ip_address(hostname)
            except ValueError:
                try:
                    resolved = socket.gethostbyname(hostname)
                except socket.gaierror as e:
                    return False, f'Could not resolve hostname {hostname}: {e}'
                if _is_blocked_ip(resolved):
                    return False, f'Hostname {hostname} resolves to private IP {resolved} (SSRF / DNS-rebinding protection)'

        return True, None
    except Exception as e:
        return False, f'Invalid URL: {e}'


def is_authorized_target(url):
    """True if this URL's host[:port] is in the authorized_targets allowlist."""
    netloc = urlparse(url).netloc.lower()
    with get_db() as conn:
        row = conn.execute(
            'SELECT id FROM authorized_targets WHERE netloc = ?', (netloc,)
        ).fetchone()
    return row is not None


def validate_scan_target(raw_url):
    """
    Normalize and validate a URL before any live request is sent to it.
    Returns (url, None) on success, or (None, (json_response, status_code)) on failure.
    Checks, in order: presence, SSRF/DNS-rebinding safety, and the
    authorized-targets allowlist — nothing gets scanned unless a human has
    explicitly confirmed ownership/permission for that host[:port].
    """
    url = (raw_url or '').strip()
    if not url:
        return None, (jsonify({'error': 'No URL provided'}), 400)
    if not url.startswith('http'):
        url = 'http://' + url

    safe, reason = is_safe_url(url)
    if not safe:
        logger.warning(f"SSRF blocked: {url} — {reason}")
        return None, (jsonify({'error': reason}), 400)

    if not is_authorized_target(url):
        netloc = urlparse(url).netloc
        logger.warning(f"Unauthorized scan attempt blocked: {url}")
        return None, (jsonify({
            'error': 'not_authorized',
            'message': f'{netloc} is not on your authorized targets list. '
                       f'Add it first, confirming you own it or have explicit permission to test it.',
            'host': netloc,
        }), 403)

    return url, None


# ============================================================
# ROUTES
# ============================================================

@app.route('/')
def index():
    return render_template('index.html')


# ── Auth routes (no @require_auth) ────────────────────────────

@app.route('/api/login', methods=['POST'])
@limiter.limit('10 per minute')
def api_login():
    """Server-side login: validates credentials, sets a session cookie."""
    data = request.get_json(silent=True) or {}
    username = data.get('username', '')
    pw_hash  = hashlib.sha256(data.get('password', '').encode()).hexdigest()

    if username == ADMIN_USERNAME and pw_hash == ADMIN_PASSWORD_HASH:
        token = secrets.token_hex(32)
        SESSIONS[token] = True
        response = jsonify({'ok': True})
        response.set_cookie(
            'wg_session', token,
            httponly=True, samesite='Strict', max_age=86400,  # 24 h
        )
        logger.info(f"Login successful for user '{username}'")
        return response

    logger.warning(f"Failed login attempt for user '{username}'")
    return jsonify({'error': 'Invalid credentials'}), 401


@app.route('/api/logout', methods=['POST'])
def api_logout():
    """Invalidate the session cookie."""
    token = request.cookies.get('wg_session')
    if token and token in SESSIONS:
        del SESSIONS[token]
    response = jsonify({'ok': True})
    response.delete_cookie('wg_session')
    return response


# ── Protected routes ──────────────────────────────────────────

@app.route('/api/analyze', methods=['POST'])
@require_auth
@limiter.limit('30 per minute')
def api_analyze():
    try:
        data = request.get_json(silent=True) or {}
        code = data.get('code', '').strip()
        if not code:
            return jsonify({'error': 'No input provided'}), 400

        result = analyze(code)

        with get_db() as conn:
            conn.execute(
                'INSERT INTO detection_history (code, predicted_vulnerable, confidence) VALUES (?,?,?)',
                (code, 1 if result['vulnerable'] else 0, result['confidence'])
            )

        return jsonify(result)

    except Exception as e:
        logger.error(f"Analyze error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/stats')
@require_auth
def api_stats():
    with get_db() as conn:
        total_vulns = conn.execute('SELECT COUNT(*) as c FROM vulnerabilities').fetchone()['c']
        total_scans = conn.execute('SELECT COUNT(*) as c FROM detection_history').fetchone()['c']
        by_severity = conn.execute(
            "SELECT severity, COUNT(*) as count FROM vulnerabilities WHERE vulnerable=1 GROUP BY severity"
        ).fetchall()
        by_cwe = conn.execute(
            "SELECT cwe, COUNT(*) as count FROM vulnerabilities WHERE vulnerable=1 GROUP BY cwe ORDER BY count DESC LIMIT 10"
        ).fetchall()
    return jsonify({
        'total_vulnerabilities': total_vulns,
        'total_scans':           total_scans,
        'by_severity':           [dict(r) for r in by_severity],
        'by_cwe':                [dict(r) for r in by_cwe],
    })


@app.route('/api/history')
@require_auth
def api_history():
    with get_db() as conn:
        rows = conn.execute(
            'SELECT * FROM detection_history ORDER BY timestamp DESC LIMIT 50'
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route('/api/targets', methods=['GET'])
@require_auth
def api_targets_list():
    with get_db() as conn:
        rows = conn.execute(
            'SELECT id, netloc, note, added_at FROM authorized_targets ORDER BY added_at DESC'
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route('/api/targets', methods=['POST'])
@require_auth
@limiter.limit('20 per minute')
def api_targets_add():
    """
    Add a target to the authorization allowlist. Requires an explicit
    confirm=true — this is the server-side enforcement of the "I own this
    system or have permission to test it" checkbox; the UI checkbox alone
    is not trusted.
    """
    data = request.get_json(silent=True) or {}
    url = (data.get('url') or '').strip()
    note = (data.get('note') or '').strip()
    confirm = data.get('confirm') is True

    if not url:
        return jsonify({'error': 'No URL/host provided'}), 400
    if not confirm:
        return jsonify({'error': 'You must confirm you own this system or have explicit permission to test it'}), 400

    if not url.startswith('http'):
        url = 'http://' + url
    parsed = urlparse(url)
    if not parsed.hostname:
        return jsonify({'error': 'Invalid URL — no hostname found'}), 400
    netloc = parsed.netloc.lower()

    try:
        with get_db() as conn:
            conn.execute(
                'INSERT OR IGNORE INTO authorized_targets (netloc, note) VALUES (?, ?)',
                (netloc, note)
            )
            row = conn.execute(
                'SELECT id, netloc, note, added_at FROM authorized_targets WHERE netloc = ?', (netloc,)
            ).fetchone()
        logger.info(f"Target authorized: {netloc}")
        return jsonify(dict(row)), 200
    except Exception as e:
        logger.error(f"Add target error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/targets/<int:target_id>', methods=['DELETE'])
@require_auth
def api_targets_delete(target_id):
    with get_db() as conn:
        conn.execute('DELETE FROM authorized_targets WHERE id = ?', (target_id,))
    return jsonify({'ok': True})


@app.route('/api/report', methods=['POST'])
@require_auth
def api_report():
    from report_generator import generate_report
    try:
        scan_data = (request.get_json(silent=True) or {}).get('scan_data', {})
        html = generate_report(scan_data)
        return html, 200, {'Content-Type': 'text/html; charset=utf-8'}
    except Exception as e:
        logger.error(f"Report generation error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/active_scan', methods=['POST'])
@require_auth
@limiter.limit('5 per minute')
def api_active_scan():
    """
    Active vulnerability scan endpoint.
    Sends real payloads to the target URL and checks responses.
    Server-side timeout: 90s (client gives 120s).
    """
    import concurrent.futures
    from active_scan import active_scan
    try:
        body = request.get_json(silent=True) or {}
        url, err = validate_scan_target(body.get('url', ''))
        if err:
            response, status = err
            return response, status

        logger.info(f"Active scan started: {url}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(active_scan, url)
            try:
                results = future.result(timeout=90)
            except concurrent.futures.TimeoutError:
                return jsonify({'error': 'Scan timed out on the server after 90s. The target may be too slow.'}), 504

        logger.info(f"Active scan finished: {url} — {len(results.get('findings', []))} findings")
        return jsonify(results)

    except Exception as e:
        logger.error(f"Active scan error: {e}")
        return jsonify({'error': str(e)}), 500


# ── GUIDED SCAN SESSIONS ───────────────────────────────────────
# In-memory store — fine for a local single-user tool. scan_id -> dict with
# target, pages (server-only response baselines), surface (client-safe
# discovered attack surface), findings, created_at. Capped/expired below so
# it can't grow unbounded across a long-running server.
GUIDED_SCANS = {}
GUIDED_SCAN_MAX = 50
GUIDED_SCAN_TTL = 2 * 60 * 60  # 2 hours


def _prune_guided_scans():
    now = time.time()
    expired = [sid for sid, s in GUIDED_SCANS.items() if now - s['created_at'] > GUIDED_SCAN_TTL]
    for sid in expired:
        del GUIDED_SCANS[sid]
    if len(GUIDED_SCANS) > GUIDED_SCAN_MAX:
        oldest = sorted(GUIDED_SCANS.items(), key=lambda kv: kv[1]['created_at'])
        for sid, _ in oldest[:len(GUIDED_SCANS) - GUIDED_SCAN_MAX]:
            del GUIDED_SCANS[sid]


def _get_guided_scan(scan_id):
    _prune_guided_scans()
    scan = GUIDED_SCANS.get(scan_id)
    if scan is None:
        return None, (jsonify({'error': 'Scan not found or expired. Start a new guided scan.'}), 410)
    return scan, None


@app.route('/api/guided/start', methods=['POST'])
@require_auth
@limiter.limit('10 per minute')
def api_guided_start():
    """
    Guided scan, stage 1 — Recon only. Validates and authorizes the target,
    then discovers its attack surface (URL params, forms, linked pages)
    WITHOUT sending any attack payloads. Returns the surface for the analyst
    to look at and choose what to actually test.
    """
    from active_scan import discover
    try:
        body = request.get_json(silent=True) or {}
        url, err = validate_scan_target(body.get('url', ''))
        if err:
            response, status = err
            return response, status

        logger.info(f"Guided scan recon started: {url}")
        disco = discover(url)
        if disco['error']:
            return jsonify({'error': disco['error']}), 502

        _prune_guided_scans()
        scan_id = uuid.uuid4().hex
        GUIDED_SCANS[scan_id] = {
            'target':     url,
            'pages':      disco['pages'],
            'surface':    disco['surface'],
            'findings':   [],
            'created_at': time.time(),
        }
        logger.info(f"Guided scan {scan_id} recon complete: {url}")
        return jsonify({'scan_id': scan_id, 'surface': disco['surface']})

    except Exception as e:
        logger.error(f"Guided scan start error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/guided/<scan_id>/test', methods=['POST'])
@require_auth
@limiter.limit('20 per minute')
def api_guided_test(scan_id):
    """
    Guided scan, stage 2 — run only the analyst-selected vulnerability
    vectors against the analyst-selected items from recon. Re-checks
    authorization in case the allowlist changed since recon.
    """
    import concurrent.futures
    from active_scan import test_selection
    try:
        scan, err = _get_guided_scan(scan_id)
        if err:
            response, status = err
            return response, status

        _, auth_err = validate_scan_target(scan['target'])
        if auth_err:
            response, status = auth_err
            return response, status

        body    = request.get_json(silent=True) or {}
        items   = body.get('items') or []
        vectors = body.get('vectors') or []
        if not items:
            return jsonify({'error': 'No items selected to test'}), 400
        if not vectors:
            return jsonify({'error': 'No vulnerability vectors selected'}), 400

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(test_selection, scan['pages'], items, vectors)
            try:
                new_findings = future.result(timeout=60)
            except concurrent.futures.TimeoutError:
                return jsonify({'error': 'Testing timed out on the server after 60s.'}), 504

        for f in new_findings:
            f.setdefault('review_status', 'unreviewed')
        scan['findings'] += new_findings

        logger.info(f"Guided scan {scan_id} tested {len(items)} item(s) — {len(new_findings)} new finding(s)")
        return jsonify({'new_findings': new_findings, 'all_findings': scan['findings']})

    except Exception as e:
        logger.error(f"Guided scan test error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/guided/<scan_id>/review', methods=['POST'])
@require_auth
def api_guided_review(scan_id):
    """
    Guided scan, stage 3 — the analyst manually confirms, dismisses, or
    flags each finding after checking the raw request/response/context
    themselves. Nothing is ever auto-confirmed.
    """
    try:
        scan, err = _get_guided_scan(scan_id)
        if err:
            response, status = err
            return response, status

        body    = request.get_json(silent=True) or {}
        index   = body.get('finding_index')
        verdict = body.get('verdict')
        note    = (body.get('note') or '').strip()

        if verdict not in ('confirmed', 'false_positive', 'needs_review'):
            return jsonify({'error': 'verdict must be confirmed, false_positive, or needs_review'}), 400
        if not isinstance(index, int) or not (0 <= index < len(scan['findings'])):
            return jsonify({'error': 'Invalid finding_index'}), 400

        scan['findings'][index]['review_status'] = verdict
        scan['findings'][index]['review_note']   = note
        return jsonify({'ok': True, 'finding': scan['findings'][index]})

    except Exception as e:
        logger.error(f"Guided scan review error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/guided/<scan_id>/report', methods=['POST'])
@require_auth
def api_guided_report(scan_id):
    """Guided scan, stage 4 — build a report from accumulated findings and
    their human review status."""
    from report_generator import generate_report
    try:
        scan, err = _get_guided_scan(scan_id)
        if err:
            response, status = err
            return response, status

        findings = scan['findings']
        severity_count = {}
        for f in findings:
            severity_count[f['severity']] = severity_count.get(f['severity'], 0) + 1

        scanned = [scan['target']] + [lp['url'] for lp in (scan['surface'].get('linked_pages') or [])]
        scan_data = {
            'target': scan['target'],
            'findings': findings,
            'scanned': scanned,
            'summary': {
                'total_findings':  len(findings),
                'confirmed_vulns': len([f for f in findings if f.get('review_status') == 'confirmed']),
                'by_severity':     severity_count,
                'pages_scanned':   len(scanned),
            },
            'scan_method': 'guided',
        }
        html = generate_report(scan_data)
        return html, 200, {'Content-Type': 'text/html; charset=utf-8'}

    except Exception as e:
        logger.error(f"Guided scan report error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/explain', methods=['POST'])
@require_auth
def api_explain():
    """
    Uses llm.py to generate an AI security explanation.
    Falls back to built-in responses if Gemini is unavailable.

    Set your Gemini key before starting (or leave unset to use fallback):
      Windows : set GEMINI_API_KEY=your-key
      Mac/Linux: export GEMINI_API_KEY=your-key
    """
    from llm import generate_explanation
    try:
        body        = request.get_json(silent=True) or {}
        scan_result = body.get('scan_result', {})
        input_text  = body.get('input_text', '')

        if not input_text:
            return jsonify({'error': 'No input provided'}), 400

        result = generate_explanation(scan_result, input_text)
        return jsonify({'result': result})

    except Exception as e:
        logger.error(f"Explain error: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================================
# START
# ============================================================

init_database()

if __name__ == '__main__':
    count = get_vuln_count()
    logger.info(f"\n{'='*60}")
    logger.info("WebGuard Backend")
    logger.info(f"{'='*60}")
    logger.info(f"  Model    : {MODEL_PATH or 'pattern-only'}")
    logger.info(f"  Database : {count} vulnerabilities")
    logger.info(f"  Frontend : http://{HOST}:{PORT}")
    logger.info(f"  Debug    : {DEBUG}")
    logger.info(f"{'='*60}\n")
    # Load the model in the background so the first ambiguous scan doesn't
    # stall for ~30s (and time out in the extension) while torch imports.
    threading.Thread(target=get_vulnerability_detector, daemon=True).start()
    app.run(debug=DEBUG, host=HOST, port=PORT)
