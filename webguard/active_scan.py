# active_scan.py
# Active vulnerability scanner module for WebGuard
# Probes URLs and forms with test payloads and analyses responses
# to confirm whether vulnerabilities are actually exploitable

import requests
import re
import time
import os
import shlex
import logging
from urllib.parse import urlparse, urlencode, parse_qs, urljoin, quote
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger('webguard.active_scan')


# ── REQUEST SETTINGS ─────────────────────────────────────────
TIMEOUT     = 8    # increased back to 8s for more reliable scans
USER_AGENT  = "WebGuard-Scanner/1.0 (Educational Security Scanner)"
HEADERS     = {"User-Agent": USER_AGENT}
MAX_PARAMS  = 50   # increased from 20 to find more entry points
MAX_FORMS   = 10   # increased from 5
MAX_LINKS   = 10   # increased from 3 to scan more of the application
MAX_THREADS = 10   # maximum concurrent requests

# ── TEST PAYLOADS ─────────────────────────────────────────────

# Fast SQLi payloads — error-based only, no sleep/wait (avoids slow blocking requests)
SQL_PAYLOADS = [
    ("'",              "basic_quote"),
    ("' OR '1'='1",   "or_true"),
    ("' OR '1'='1'--", "comment_bypass"),
    ("' UNION SELECT NULL--", "union_probe"),
    ("1'",             "quote_append"),
]

# Slow time-based payloads — only used when explicitly requested
SQL_PAYLOADS_SLOW = [
    ("1 AND SLEEP(1)","time_based"),
    ("1 WAITFOR DELAY '0:0:3'--", "time_based_mssql"),
]

XSS_PAYLOADS = [
    ("<script>webguard_xss_test</script>", "script_tag"),
    ("<img src=x onerror=webguard_xss_test>", "img_onerror"),
    ("javascript:webguard_xss_test",        "js_proto"),
    ("webguard_xss_test<b>",               "html_inject"),
]

PATH_PAYLOADS = [
    ("../../../../etc/passwd",              "unix_traversal"),
    ("..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "win_traversal"),
    ("%2e%2e%2f%2e%2e%2fetc%2fpasswd",     "encoded_traversal"),
]

CMD_PAYLOADS = [
    (";echo webguard_cmd_test",            "semicolon"),
    ("|echo webguard_cmd_test",            "pipe"),
    ("&&echo webguard_cmd_test",           "and"),
]

# Open-redirect payloads point at a harmless, obviously-attacker-controlled
# marker host. A vulnerable endpoint will either 302 to it (Location header)
# or reflect it into a redirect in the body.
REDIRECT_MARKER   = "webguard-evil.example"
REDIRECT_PAYLOADS = [
    (f"https://{REDIRECT_MARKER}/",  "absolute_url"),
    (f"//{REDIRECT_MARKER}/",         "protocol_relative"),
]
# A marker echoed as plain text is not a redirect. Body reflection only counts
# when it lands in something that can navigate: a meta refresh, a JS location
# change / window.open, or a link/form target.
REDIRECT_SINK_RE = re.compile(
    r'(?:http-equiv\s*=\s*["\']?refresh[^>]*?url\s*=\s*["\']?'
    r'|(?:location(?:\.href)?\s*=|location\.(?:replace|assign)\(|window\.open\()\s*["\']'
    r'|(?:href|action|formaction)\s*=\s*["\']?)'
    r'(?:https?:)?//' + re.escape(REDIRECT_MARKER),
    re.IGNORECASE,
)

# ── CWE → OWASP TOP 10 (2021) ────────────────────────────────
# Maps each detected weakness to its OWASP Top 10 category so findings speak
# the vocabulary reviewers and clients expect, not just raw CWE numbers.
CWE_OWASP = {
    'CWE-89':  'A03:2021 – Injection',
    'CWE-79':  'A03:2021 – Injection',
    'CWE-78':  'A03:2021 – Injection',
    'CWE-22':  'A01:2021 – Broken Access Control',
    'CWE-601': 'A01:2021 – Broken Access Control',
    'CWE-918': 'A10:2021 – Server-Side Request Forgery (SSRF)',
}

def owasp_for(cwe):
    """Return the OWASP Top 10 (2021) category for a CWE id, or 'Unmapped'."""
    return CWE_OWASP.get((cwe or '').upper().strip(), 'Unmapped')

# ── SQL ERROR SIGNATURES ─────────────────────────────────────

SQL_ERRORS = [
    # MySQL
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"mysql_fetch",
    r"mysql_num_rows",
    r"supplied argument is not a valid mysql",
    r"check the manual that corresponds to your mysql server version",
    # MSSQL / OLE DB — classic ASP + IIS (testasp.vulnweb.com style)
    r"microsoft ole db provider for sql server",
    r"microsoft ole db provider for odbc drivers",
    r"odbc microsoft access driver",
    r"error '8004[0-9a-f]{4}'",          # OLE DB error codes e.g. '80040e14'
    r"80040e14",                           # Explicit: unclosed quotation mark
    r"80040e07",                           # Explicit: conversion failed
    r"error in '.*\.asp'",               # ASP line reference in error page
    r"syntax error converting",
    r"unclosed quotation mark",
    r"conversion failed when converting",  # MSSQL type mismatch
    r"invalid column name",                # MSSQL column reference error
    r"\[microsoft\]\[odbc sql server driver\]",
    r"oledbexception",
    r"microsoft jet database engine",
    r"syntax error in string in query expression",
    r"syntax error \(missing operator\) in query expression",
    r"server error in '/' application",
    r"incorrect syntax near",              # MSSQL generic syntax error
    r"quoted string not properly terminated",  # Oracle / MSSQL
    r"microsoft vbscript runtime error",
    r"type mismatch",
    # Oracle
    r"ora-[0-9]{4,5}",
    r"oracle error",
    # PostgreSQL
    r"pg_query\(\)",
    r"unterminated quoted string at or near",
    r"severity: fatal",
    # SQLite
    r"sqlite_error",
    r"sqlite3\.operationalerror",
    # Generic
    r"sql syntax.*mysql",
    r"warning.*\Wmysqli?_",
    r"valid mysql result",
    r"mysqlclient",
    r"db_exception",
    r"internal server error",  # Often mapped to 500 but sometimes in body
]

# ── HELPER FUNCTIONS ─────────────────────────────────────────

def safe_get(url, params=None, timeout=TIMEOUT, allow_redirects=True):
    """Make a GET request, return (response, error).

    `allow_redirects=False` is used by the open-redirect test so the raw
    3xx Location header can be inspected instead of being auto-followed.
    """
    try:
        r = requests.get(url, params=params, headers=HEADERS,
                         timeout=timeout, allow_redirects=allow_redirects, verify=False)
        if r is None:
            logger.debug(f"CRITICAL: requests.get returned None for {url}")
        return r, None
    except Exception as e:
        logger.debug(f"safe_get EXCEPTION: {type(e).__name__}: {str(e)}")
        return None, str(e)

def safe_post(url, data, timeout=TIMEOUT):
    """Make a POST request, return (response, error)."""
    try:
        r = requests.post(url, data=data, headers=HEADERS,
                          timeout=timeout, allow_redirects=True, verify=False)
        return r, None
    except Exception as e:
        return None, str(e)

def check_sql_error(text, status_code=200):
    """
    Check if a response shows signs of SQL injection.

    Returns (matched, pattern, strong):
      strong=True  -> a real SQL error string was found: hard, confirmable proof.
      strong=False -> only a bare HTTP 500 on the payload: a weak lead, since a
                      500 has many unrelated causes. Reported for review, NOT as
                      a confirmed vulnerability.
    """
    text_lower = text.lower()
    for pattern in SQL_ERRORS:
        if re.search(pattern, text_lower):
            return True, pattern, True
    # A bare 500 (no SQL error text) is a hint, not proof — keep it, but weak.
    if status_code == 500:
        return True, 'HTTP 500 server error on payload (no SQL error text — many possible causes)', False
    return False, None, False

def check_reflected(payload, response_text):
    """Check if payload is reflected in the response."""
    return payload.lower() in response_text.lower()

def check_xss_reflected(payload, response_text):
    """Reflection only means XSS if the payload can still run where it lands.

    Payloads carrying markup must come back with their '<' intact (escaping
    neutralises them). A bare javascript: URL has no markup, so it survives
    escaping unchanged; it only executes inside a navigable attribute.
    """
    if '<' in payload:
        return check_reflected(payload, response_text)
    return re.search(r'(?:href|src|action|formaction)\s*=\s*["\']?\s*' + re.escape(payload),
                     response_text, re.IGNORECASE) is not None

def check_cmd_executed(payload, response_text):
    """
    Check if a command-injection marker was actually executed rather than
    merely reflected as literal text. Pages that naively echo user input
    back (e.g. an XSS-style reflection endpoint) will contain the *whole*
    payload string verbatim, including the marker — that's not command
    execution. Real execution only leaks the command's stdout (the bare
    marker), with the shell metacharacters and command name stripped out,
    so requiring the full payload to be ABSENT while the marker is PRESENT
    tells the two apart.
    """
    # Checking for the whole payload is not enough: an HTML-escaping page turns
    # "&&echo webguard_cmd_test" into "&amp;&amp;echo webguard_cmd_test", so the
    # payload looks absent while the marker is still just echoed text. Require
    # a bare marker that is not directly preceded by the "echo" that sent it.
    return re.search(r'(?<!echo )webguard_cmd_test', response_text.lower()) is not None

def check_time_diff(baseline_time, test_time, threshold=2.0):
    """Check if response took significantly longer (time-based SQLi)."""
    return test_time - baseline_time >= threshold

def extract_context(text, needle, radius=200):
    """Return a snippet of `text` around the first occurrence of `needle`
    (case-insensitive), so a human can eyeball the actual reflection/error
    instead of trusting a one-line evidence string."""
    if not text or not needle:
        return ''
    idx = text.lower().find(needle.lower())
    if idx == -1:
        return text[:radius * 2]
    start = max(0, idx - radius)
    end = min(len(text), idx + len(needle) + radius)
    return text[start:end]

def _build_curl(method, url, params_or_data):
    """Render a copy-pasteable curl command that reproduces this exact probe,
    so the analyst can re-run it independently of WebGuard to verify a finding.
    Uses POSIX single-quote quoting (works in bash / git-bash / WSL)."""
    method = (method or 'GET').upper()
    ua = HEADERS.get('User-Agent', '')
    if method == 'GET':
        full = url
        if params_or_data:
            sep = '&' if '?' in url else '?'
            full = f"{url}{sep}{urlencode(params_or_data)}"
        return f"curl -sk -A {shlex.quote(ua)} {shlex.quote(full)}"
    data = urlencode(params_or_data) if isinstance(params_or_data, dict) else str(params_or_data or '')
    return (f"curl -sk -X {method} -A {shlex.quote(ua)} "
            f"--data {shlex.quote(data)} {shlex.quote(url)}")


def _capture_evidence(method, url, params_or_data, resp, evidence_needle=''):
    """Build the raw_request / raw_response / context_snippet block attached
    to every finding, so the analyst can manually verify it instead of just
    trusting the scanner's verdict. Includes a copy-pasteable curl command
    that reproduces the probe."""
    return {
        'curl_command': _build_curl(method, url, params_or_data),
        'raw_request': {
            'method': method,
            'url': url,
            'params': params_or_data,
            'headers': dict(HEADERS),
        },
        'raw_response': {
            'status_code': resp.status_code if resp is not None else None,
            'headers': dict(list(resp.headers.items())[:15]) if resp is not None else {},
            'body_snippet': (resp.text[:2000] if resp is not None else ''),
        },
        'context_snippet': extract_context(resp.text if resp is not None else '', evidence_needle),
    }

def extract_forms(base_url, html):
    """Extract all forms from the page."""
    soup   = BeautifulSoup(html, 'html.parser')
    parsed = urlparse(base_url)
    base   = f"{parsed.scheme}://{parsed.netloc}"
    forms  = []
    for form in soup.find_all('form'):
        action = form.get('action', '')
        if not action:
            action = base_url
        elif action.startswith('/'):
            action = base + action
        elif not action.startswith('http'):
            action = urljoin(base_url, action)

        method = form.get('method', 'get').lower()
        fields = {}
        for inp in form.find_all(['input', 'textarea', 'select']):
            name = inp.get('name')
            if not name: continue
            itype = inp.get('type', 'text').lower()
            if itype in ('submit', 'button', 'image', 'reset'): continue
            # Retain hidden fields like __VIEWSTATE exactly
            if itype == 'hidden':
                fields[name] = inp.get('value', '')
            else:
                fields[name] = inp.get('value', 'test')

        if fields:
            forms.append({'action': action, 'method': method, 'fields': fields})

    return forms[:MAX_FORMS]

# ── ACTIVE TESTS ─────────────────────────────────────────────

def test_sql_injection_url(url, param, baseline_text, baseline_time, slow=False):
    """Test a URL parameter for SQL injection.

    `slow=False` (default) only runs the fast error-based payloads. Pass
    `slow=True` to additionally run the time-based blind payloads — these
    deliberately make the target sleep, so they're opt-in only.
    """
    parsed   = urlparse(url)
    params   = parse_qs(parsed.query, keep_blank_values=True)
    findings = []
    payloads = list(SQL_PAYLOADS) + (list(SQL_PAYLOADS_SLOW) if slow else [])

    for payload, label in payloads:
        test_params = {k: v[0] for k, v in params.items()}
        test_params[param] = payload
        base_url = url.split('?')[0]

        t0 = time.time()
        resp, err = safe_get(base_url, params=test_params)
        elapsed = time.time() - t0

        if err:
            continue
        if resp is None:
            continue

        text = resp.text
        has_error, matched_pattern, strong = check_sql_error(text, resp.status_code)
        is_time_based = (payload, label) in SQL_PAYLOADS_SLOW and check_time_diff(baseline_time, elapsed)

        if has_error:
            findings.append({
                'type':       'SQL Injection (Error-Based)' if strong
                              else 'SQL Injection (Suspected — HTTP 500)',
                'url':        url,
                'vector':     'URL Parameter',
                'param':      param,
                'payload':    payload,
                'payload_name': label,
                'evidence':   (f"SQL error pattern matched: {matched_pattern}" if strong
                               else f"{matched_pattern} — verify manually, not confirmed"),
                # SQLi impact is critical, but a bare 500 isn't proof of it.
                'severity':   'CRITICAL' if strong else 'MEDIUM',
                'cwe':        'CWE-89',
                'confirmed':  strong,
                **_capture_evidence('GET', base_url, test_params, resp, matched_pattern),
            })
            break

        if is_time_based:
            findings.append({
                'type':      'SQL Injection (Time-Based Blind)',
                'url':        url,
                'vector':     'URL Parameter',
                'param':      param,
                'payload':   payload,
                'payload_name': label,
                'evidence':  f"Response delayed {elapsed:.1f}s vs baseline {baseline_time:.1f}s",
                'severity':  'CRITICAL',
                'cwe':       'CWE-89',
                'confirmed': True,
                **_capture_evidence('GET', base_url, test_params, resp),
            })
            break

    return findings


def test_xss_url(url, param, baseline_text):
    """Test a URL parameter for reflected XSS."""
    parsed   = urlparse(url)
    params   = parse_qs(parsed.query, keep_blank_values=True)
    findings = []

    for payload, label in XSS_PAYLOADS:
        test_params = {k: v[0] for k, v in params.items()}
        test_params[param] = payload
        base_url = url.split('?')[0]

        resp, err = safe_get(base_url, params=test_params)
        if err or resp is None: continue

        if check_xss_reflected(payload, resp.text):
            findings.append({
                'type':      'Cross-Site Scripting (Reflected XSS)',
                'url':        url,
                'vector':     'URL Parameter',
                'param':     param,
                'payload':   payload,
                'payload_name': label,
                'evidence':  f"Payload reflected in response body",
                'severity':  'HIGH',
                'cwe':       'CWE-79',
                'confirmed': True,
                **_capture_evidence('GET', base_url, test_params, resp, payload),
            })
            break

    return findings


def test_path_traversal_url(url, param):
    """Test a URL parameter for path traversal."""
    parsed   = urlparse(url)
    params   = parse_qs(parsed.query, keep_blank_values=True)
    findings = []

    for payload, label in PATH_PAYLOADS:
        test_params = {k: v[0] for k, v in params.items()}
        test_params[param] = payload
        base_url = url.split('?')[0]

        resp, err = safe_get(base_url, params=test_params)
        if err or resp is None: continue

        text = resp.text.lower()
        # Look for common platform-specific strings in sensitive files
        indicators = [
            'root:x:0:0', 'bin/bash', 'bin/sh',     # Linux /etc/passwd
            '[boot loader]', 'multi(0)disk(0)',    # Windows boot.ini
            '127.0.0.1 localhost', '::1',          # Windows/Linux hosts
            '[extensions]', '[fonts]',             # Windows win.ini
            'uid=', 'gid=', 'groups='              # Output of 'id' command or similar
        ]
        matched = next((ind for ind in indicators if ind in text), None)
        if matched:
            findings.append({
                'type':      'Path Traversal',
                'url':        url,
                'vector':     'URL Parameter',
                'param':     param,
                'payload':   payload,
                'payload_name': label,
                'evidence':  'Sensitive system indicators detected in response body',
                'severity':  'HIGH',
                'cwe':       'CWE-22',
                'confirmed': True,
                **_capture_evidence('GET', base_url, test_params, resp, matched),
            })
            break

    return findings


def test_command_injection_url(url, param):
    """Test a URL parameter for OS command injection: the marker must show
    up as *executed* command output, not just reflected input text (see
    check_cmd_executed)."""
    parsed   = urlparse(url)
    params   = parse_qs(parsed.query, keep_blank_values=True)
    findings = []

    for payload, label in CMD_PAYLOADS:
        test_params = {k: v[0] for k, v in params.items()}
        test_params[param] = payload
        base_url = url.split('?')[0]

        resp, err = safe_get(base_url, params=test_params)
        if err or resp is None: continue

        if check_cmd_executed(payload, resp.text):
            findings.append({
                'type':      'OS Command Injection',
                'url':        url,
                'vector':     'URL Parameter',
                'param':     param,
                'payload':   payload,
                'payload_name': label,
                'evidence':  "Command marker 'webguard_cmd_test' echoed back in response body",
                'severity':  'CRITICAL',
                'cwe':       'CWE-78',
                'confirmed': True,
                **_capture_evidence('GET', base_url, test_params, resp, 'webguard_cmd_test'),
            })
            break

    return findings


def test_open_redirect_url(url, param):
    """Test a URL parameter for an open redirect (CWE-601).

    Redirects are NOT auto-followed so the raw Location header can be read.
    A 3xx pointing at the attacker-controlled marker host is strong evidence
    (confirmed); a marker merely reflected into the body is weaker and left
    for manual review.
    """
    parsed   = urlparse(url)
    params   = parse_qs(parsed.query, keep_blank_values=True)
    findings = []

    for payload, label in REDIRECT_PAYLOADS:
        test_params = {k: v[0] for k, v in params.items()}
        test_params[param] = payload
        base_url = url.split('?')[0]

        resp, err = safe_get(base_url, params=test_params, allow_redirects=False)
        if err or resp is None: continue

        location    = resp.headers.get('Location', '') or ''
        in_location = REDIRECT_MARKER in location.lower()
        in_body     = bool(REDIRECT_SINK_RE.search(resp.text))

        if in_location or in_body:
            findings.append({
                'type':      'Open Redirect',
                'url':        url,
                'vector':     'URL Parameter',
                'param':     param,
                'payload':   payload,
                'payload_name': label,
                'evidence':  (f"HTTP {resp.status_code} redirect to attacker-controlled host via Location: {location}"
                              if in_location else
                              "Attacker-controlled URL reflected into a redirect/link sink in the body (verify it is acted on)"),
                'severity':  'MEDIUM',
                'cwe':       'CWE-601',
                # A Location header is proof; body-only reflection is a lead, not proof.
                'confirmed': in_location,
                **_capture_evidence('GET', base_url, test_params, resp, REDIRECT_MARKER),
            })
            break

    return findings


def test_form(form, baseline_text='', vectors=None):
    """Test a form's fields for SQL injection, XSS and command injection.

    `vectors` restricts which checks run (subset of {'sqli','xss','cmd'});
    None/omitted runs all of them (used by the legacy full-auto scan).
    """
    if vectors is None:
        vectors = {'sqli', 'xss', 'cmd'}
    findings = []
    action   = form['action']
    method   = form['method']
    fields   = form['fields']

    def send(test_data):
        if method == 'post':
            return safe_post(action, test_data)
        return safe_get(action, params=test_data)

    for field_name in list(fields.keys())[:5]:
        if 'sqli' in vectors:
            for payload, label in SQL_PAYLOADS[:3]:
                test_data = dict(fields)
                test_data[field_name] = payload
                resp, err = send(test_data)
                if err or resp is None: continue

                has_error, pattern, strong = check_sql_error(resp.text, resp.status_code)
                if has_error:
                    findings.append({
                        'type':      'SQL Injection (Form - Error-Based)' if strong
                                     else 'SQL Injection (Form - Suspected HTTP 500)',
                        'url':       action,
                        'vector':    f"Form ({method.upper()})",
                        'param':     field_name,
                        'payload':   payload,
                        'payload_name': label,
                        'evidence':  (f"SQL error in form response: {pattern}" if strong
                                      else f"{pattern} — verify manually, not confirmed"),
                        'severity':  'CRITICAL' if strong else 'MEDIUM',
                        'cwe':       'CWE-89',
                        'confirmed': strong,
                        'form':      action,
                        **_capture_evidence(method.upper(), action, test_data, resp, pattern),
                    })
                    break

        if 'xss' in vectors:
            for payload, label in XSS_PAYLOADS[:2]:
                test_data = dict(fields)
                test_data[field_name] = payload
                resp, err = send(test_data)
                if err or resp is None: continue

                if check_xss_reflected(payload, resp.text):
                    findings.append({
                        'type':      'XSS (Form - Reflected)',
                        'url':       action,
                        'vector':    f"Form ({method.upper()})",
                        'param':     field_name,
                        'payload':   payload,
                        'payload_name': label,
                        'evidence':  'XSS payload reflected in form response',
                        'severity':  'HIGH',
                        'cwe':       'CWE-79',
                        'confirmed': True,
                        'form':      action,
                        **_capture_evidence(method.upper(), action, test_data, resp, payload),
                    })
                    break

        if 'cmd' in vectors:
            for payload, label in CMD_PAYLOADS:
                test_data = dict(fields)
                test_data[field_name] = payload
                resp, err = send(test_data)
                if err or resp is None: continue

                if check_cmd_executed(payload, resp.text):
                    findings.append({
                        'type':      'OS Command Injection (Form)',
                        'url':       action,
                        'vector':    f"Form ({method.upper()})",
                        'param':     field_name,
                        'payload':   payload,
                        'payload_name': label,
                        'evidence':  "Command marker 'webguard_cmd_test' echoed back in response body",
                        'severity':  'CRITICAL',
                        'cwe':       'CWE-78',
                        'confirmed': True,
                        'form':      action,
                        **_capture_evidence(method.upper(), action, test_data, resp, 'webguard_cmd_test'),
                    })
                    break

    return findings


# ── GUIDED SCAN: DISCOVERY (no payloads sent) ────────────────

def discover(target_url):
    """
    Recon-only phase: fetch the target page and enumerate its attack surface
    (URL parameters, forms, and linked pages with *their* params/forms).
    Sends zero attack payloads — this is what the guided workflow shows the
    analyst before they choose what to actually test.

    Returns {'target', 'error', 'pages', 'surface'} where `pages` maps
    url -> {'text','time'} baselines (kept server-side, needed by
    test_selection) and `surface` is the client-safe discovered structure.
    """
    t0 = time.time()
    resp, err = safe_get(target_url)
    baseline_time = time.time() - t0

    if err or not resp:
        return {'target': target_url, 'error': f"Could not reach target: {err}", 'pages': {}, 'surface': None}

    pages = {target_url: {'text': resp.text, 'time': baseline_time}}

    parsed = urlparse(target_url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    forms  = extract_forms(target_url, resp.text)

    linked_pages = []
    for link in extract_links_with_params(target_url, resp.text)[:MAX_LINKS]:
        link_resp, link_err = safe_get(link)
        if link_err or link_resp is None:
            continue
        pages[link] = {'text': link_resp.text, 'time': 0.0}
        link_params = parse_qs(urlparse(link).query, keep_blank_values=True)
        linked_pages.append({
            'url': link,
            'url_params': list(link_params.keys())[:3],
            'forms': extract_forms(link, link_resp.text)[:3],
        })

    surface = {
        'target': target_url,
        'url_params': list(params.keys())[:MAX_PARAMS],
        'forms': forms,
        'linked_pages': linked_pages,
    }
    return {'target': target_url, 'error': None, 'pages': pages, 'surface': surface}


# ── GUIDED SCAN: TARGETED TESTING ─────────────────────────────

def test_selection(pages, items, vectors):
    """
    Run only the analyst-chosen vectors against the analyst-chosen items
    from a prior discover() call.

    pages: dict url -> {'text','time'} baselines, as returned by discover().
    items: list of selection dicts, either
      {'kind': 'url_param', 'url': <page url>, 'param': <name>}
      {'kind': 'form', 'url': <page url>, 'action':.., 'method':.., 'fields': {..}}
    vectors: subset of {'sqli', 'sqli_slow', 'xss', 'path', 'cmd'}.
    """
    vectors = set(vectors or [])
    findings = []

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = []
        for item in items:
            kind = item.get('kind')

            if kind == 'url_param':
                url, param = item.get('url'), item.get('param')
                if not url or not param:
                    continue
                page = pages.get(url, {})
                baseline_text = page.get('text', '')
                baseline_time = page.get('time', 0.0)

                if 'sqli' in vectors or 'sqli_slow' in vectors:
                    futures.append(executor.submit(
                        test_sql_injection_url, url, param, baseline_text, baseline_time, 'sqli_slow' in vectors
                    ))
                if 'xss' in vectors:
                    futures.append(executor.submit(test_xss_url, url, param, baseline_text))
                if 'path' in vectors:
                    futures.append(executor.submit(test_path_traversal_url, url, param))
                if 'cmd' in vectors:
                    futures.append(executor.submit(test_command_injection_url, url, param))
                if 'redirect' in vectors:
                    futures.append(executor.submit(test_open_redirect_url, url, param))

            elif kind == 'form':
                form = {
                    'action': item.get('action'),
                    'method': (item.get('method') or 'get').lower(),
                    'fields': item.get('fields') or {},
                }
                form_vectors = vectors & {'sqli', 'xss', 'cmd'}
                if form['action'] and form['fields'] and form_vectors:
                    futures.append(executor.submit(test_form, form, '', form_vectors))

        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    findings += result
            except Exception:
                pass  # a single failed probe shouldn't abort the batch

    seen = set()
    unique = []
    for f in findings:
        key = (f['type'], f['param'], f.get('form', ''))
        if key not in seen:
            seen.add(key)
            unique.append(f)

    # Tag each finding with its OWASP Top 10 category (derived from CWE).
    for f in unique:
        f.setdefault('owasp', owasp_for(f.get('cwe')))
    return unique


# ── LEGACY: FULL-AUTO SCAN (discover + test everything) ───────

def active_scan(target_url):
    """
    Backward-compatible full-auto scan used by /api/active_scan: discover()
    the whole attack surface, then test_selection() every discovered item
    with every fast vector. The guided workflow (discover() + test_selection()
    driven by analyst choices) is the preferred path for new code — this
    exists so the legacy endpoint keeps working.
    """
    t0 = time.time()
    disco = discover(target_url)
    results = {'target': target_url, 'findings': [], 'scanned': [], 'error': disco['error'], 'summary': {}}
    if disco['error']:
        return results

    surface, pages = disco['surface'], disco['pages']
    items = [{'kind': 'url_param', 'url': target_url, 'param': p} for p in surface['url_params']]
    results['scanned'].append(target_url)

    for form in surface['forms']:
        results['scanned'].append(f"FORM: {form['action']} [{form['method'].upper()}]")
        items.append({'kind': 'form', 'url': target_url, **form})

    for linked in surface['linked_pages']:
        results['scanned'].append(linked['url'])
        items += [{'kind': 'url_param', 'url': linked['url'], 'param': p} for p in linked['url_params']]
        for form in linked['forms']:
            results['scanned'].append(f"FORM: {form['action']} [{form['method'].upper()}]")
            items.append({'kind': 'form', 'url': linked['url'], **form})

    # Time-based blind SQLi stays opt-in even in the legacy full-auto path —
    # it deliberately makes the target sleep and shouldn't fire without intent.
    findings = test_selection(pages, items, {'sqli', 'xss', 'path', 'cmd', 'redirect'})
    results['findings'] = findings

    severity_count = {}
    for f in findings:
        severity_count[f['severity']] = severity_count.get(f['severity'], 0) + 1

    results['summary'] = {
        'total_findings':   len(findings),
        'confirmed_vulns':  len([f for f in findings if f.get('confirmed')]),
        'by_severity':      severity_count,
        'pages_scanned':    len(results['scanned']),
        'duration_seconds': round(time.time() - t0, 2),
    }
    return results


def extract_links_with_params(base_url, html):
    """Extract internal links that have query parameters."""
    soup   = BeautifulSoup(html, 'html.parser')
    parsed = urlparse(base_url)
    base   = f"{parsed.scheme}://{parsed.netloc}"
    links  = []
    for tag in soup.find_all('a', href=True):
        href = tag['href']
        if href.startswith('/'):
            href = base + href
        elif not href.startswith('http'):
            href = urljoin(base_url, href)
        if parsed.netloc in href and '?' in href:
            links.append(href)
    # Sort links and remove duplicates while maintaining order for determinism
    seen = set()
    cleaned_links = []
    for l in links:
        if l not in seen:
            seen.add(l)
            cleaned_links.append(l)
    
    return cleaned_links[:15]   # scan up to 15 unique links
