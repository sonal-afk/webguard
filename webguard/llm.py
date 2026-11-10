# llm.py
# AI explanation module for WebGuard
# Uses Google Gemini (free) to explain vulnerabilities and suggest fixes
# Falls back to built-in explanations if the API is unavailable
#
# Setup:
#   pip install google-genai
#   set GEMINI_API_KEY=YOUR_KEY   (get free key at aistudio.google.com)

import os
import json
import logging

try:
    from google import genai
except ImportError:
    genai = None

logger = logging.getLogger('webguard.llm')

# Older Gemini models get retired; override in .env without touching code.
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

_client = None

def _get_client():
    global _client
    if _client is None:
        api_key = os.getenv("GEMINI_API_KEY", "")
        if api_key and genai is not None:
            _client = genai.Client(api_key=api_key)
    return _client


def generate_explanation(scan_result: dict, input_text: str) -> dict:
    """
    Generate an AI security explanation for a scan result.
    Returns a dict ready to be sent as JSON to the frontend.
    Falls back safely if Gemini is unavailable or key not set.
    """
    is_vuln    = scan_result.get('vulnerable', False)
    patterns   = scan_result.get('patterns', [])
    confidence = round((scan_result.get('confidence', 0)) * 100, 1)

    pattern_list = ', '.join(
        f"{p['type']} ({p['cwe']})" for p in patterns
    ) if patterns else 'none detected by pattern engine'

    prompt = _build_prompt(is_vuln, input_text, pattern_list, confidence)

    client = _get_client()
    if client is None:
        logger.info("No GEMINI_API_KEY set — using fallback response")
        return _fallback_response(is_vuln, patterns)

    try:
        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt,
        )
        raw = response.text.strip()
        raw = raw.replace("```json", "").replace("```", "").strip()
        return json.loads(raw)

    except Exception as e:
        logger.error(f"LLM error: {e}")
        return _fallback_response(is_vuln, patterns)


# ── PROMPT BUILDER ──────────────────────────────────────────────

def _build_prompt(is_vuln, input_text, pattern_list, confidence):
    if is_vuln:
        return f"""A web vulnerability scanner flagged this input as VULNERABLE ({confidence}% confidence).

Input scanned:
{input_text[:400]}

Attack patterns detected: {pattern_list}

Respond ONLY with this JSON structure:
{{
  "attack_type": "short name e.g. SQL Injection",
  "severity": "CRITICAL or HIGH or MEDIUM or LOW",
  "explanation": "2-3 sentences explaining exactly why this is dangerous and what an attacker could do",
  "what_attacker_gets": "one sentence — what data or access the attacker gains",
  "prevention": [
    "First specific fix with code example if possible",
    "Second specific fix",
    "Third specific fix"
  ],
  "cwe": "CWE-XX",
  "owasp": "A0X:2021 - Category Name"
}}"""
    else:
        return f"""A web vulnerability scanner marked this input as SAFE ({confidence}% confidence).

Input scanned:
{input_text[:400]}

Respond ONLY with this JSON structure:
{{
  "explanation": "2 sentences explaining why this looks safe",
  "good_practices": ["practice 1", "practice 2", "practice 3"],
  "still_watch_for": "one sentence about edge cases to still be careful about"
}}"""


# ── FALLBACK RESPONSES ───────────────────────────────────────────

def _fallback_response(is_vuln: bool, patterns: list) -> dict:
    """
    Built-in fallback when Gemini is unavailable.
    Uses detected patterns to give a relevant response.
    """
    if not is_vuln:
        return {
            "explanation": (
                "The input does not contain known attack patterns and appears to be a "
                "legitimate web request. No malicious payloads, injections, or traversal "
                "sequences were detected by the pattern engine."
            ),
            "good_practices": [
                "Continue validating all user inputs on the server side",
                "Use parameterised queries for all database interactions",
                "Apply Content Security Policy (CSP) headers on your web server"
            ],
            "still_watch_for": (
                "Even safe-looking inputs can carry encoded payloads — "
                "always decode and sanitise before processing."
            )
        }

    # Pick the most relevant fallback based on first detected pattern
    ptype = patterns[0]['type'] if patterns else ''

    FALLBACKS = {
        'SQL Injection': {
            "attack_type": "SQL Injection",
            "severity": "CRITICAL",
            "explanation": (
                "The input contains SQL metacharacters or keywords that can break out of "
                "the intended query and execute arbitrary SQL commands. An attacker can "
                "bypass authentication, dump database contents, or delete data entirely."
            ),
            "what_attacker_gets": (
                "Full read/write access to the database, potential authentication bypass, "
                "and possible remote code execution via SQL features like xp_cmdshell."
            ),
            "prevention": [
                "Use parameterised queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
                "Use an ORM (SQLAlchemy, Django ORM) which handles escaping automatically",
                "Apply a Web Application Firewall (WAF) to block common SQL injection patterns"
            ],
            "cwe": "CWE-89",
            "owasp": "A03:2021 - Injection"
        },
        'XSS': {
            "attack_type": "Cross-Site Scripting (XSS)",
            "severity": "HIGH",
            "explanation": (
                "The input contains JavaScript or HTML tags that will be executed in a "
                "victim's browser. Attackers use XSS to steal session cookies, redirect "
                "users to phishing pages, or perform actions on their behalf."
            ),
            "what_attacker_gets": (
                "Session cookies, stored credentials, ability to perform actions as the "
                "victim, and potential full account takeover."
            ),
            "prevention": [
                "Escape output: use htmlspecialchars($input, ENT_QUOTES) in PHP or html.escape() in Python",
                "Set Content-Security-Policy header: Content-Security-Policy: default-src 'self'",
                "Use a trusted sanitiser library like DOMPurify on the frontend"
            ],
            "cwe": "CWE-79",
            "owasp": "A03:2021 - Injection"
        },
        'Path Traversal': {
            "attack_type": "Path Traversal",
            "severity": "HIGH",
            "explanation": (
                "The input contains ../ sequences designed to escape the intended directory "
                "and access files outside the web root. Attackers use this to read sensitive "
                "server files like /etc/passwd or application config files with credentials."
            ),
            "what_attacker_gets": (
                "Read access to arbitrary files on the server including credentials, "
                "private keys, and configuration files."
            ),
            "prevention": [
                "Validate file paths: use os.path.realpath() and ensure it starts with your allowed base directory",
                "Never pass raw user input directly to file system functions",
                "Maintain a whitelist of allowed filenames rather than blocking traversal sequences"
            ],
            "cwe": "CWE-22",
            "owasp": "A01:2021 - Broken Access Control"
        },
        'Command Injection': {
            "attack_type": "Command Injection",
            "severity": "CRITICAL",
            "explanation": (
                "The input contains shell metacharacters or commands designed to be executed "
                "by the operating system. If the server passes this input to a shell, the "
                "attacker gains full control of the server."
            ),
            "what_attacker_gets": (
                "Remote code execution on the server — attacker can read files, "
                "install malware, pivot to internal systems, or take the server fully offline."
            ),
            "prevention": [
                "Never pass user input to shell commands. Use language APIs instead of shell: subprocess.run(['ls', path], shell=False)",
                "If shell is unavoidable, use shlex.quote() to escape input",
                "Run the web server process with minimal OS privileges (least privilege principle)"
            ],
            "cwe": "CWE-78",
            "owasp": "A03:2021 - Injection"
        },
        'SSRF': {
            "attack_type": "Server-Side Request Forgery (SSRF)",
            "severity": "HIGH",
            "explanation": (
                "The input points the server at an internal address, cloud metadata endpoint, "
                "or unusual URL scheme. If the server fetches URLs on the user's behalf, an "
                "attacker can make it reach systems that are not exposed to the internet."
            ),
            "what_attacker_gets": (
                "Access to internal services and cloud metadata, which often exposes "
                "temporary credentials and lets the attacker move deeper into the network."
            ),
            "prevention": [
                "Allow-list the exact hosts and schemes the server may fetch; reject everything else",
                "Resolve the hostname and block private, loopback and link-local IP ranges (e.g. 169.254.169.254)",
                "Disable redirects on server-side fetches, or re-validate the target after each redirect"
            ],
            "cwe": "CWE-918",
            "owasp": "A10:2021 - Server-Side Request Forgery"
        },
        'Open Redirect': {
            "attack_type": "Open Redirect",
            "severity": "MEDIUM",
            "explanation": (
                "The input supplies a redirect target that may send users to an external site. "
                "Attackers use trusted-looking links on your domain to forward victims to "
                "phishing or malware pages."
            ),
            "what_attacker_gets": (
                "Credibility for phishing links, and in OAuth flows potentially stolen "
                "authorisation codes or tokens."
            ),
            "prevention": [
                "Only redirect to relative paths or to an allow-list of known destinations",
                "Map redirect targets to IDs (e.g. ?next=dashboard) instead of accepting raw URLs",
                "Compare the parsed target origin with your own origin before redirecting"
            ],
            "cwe": "CWE-601",
            "owasp": "A01:2021 - Broken Access Control"
        },
        'XXE': {
            "attack_type": "XML External Entity (XXE) Injection",
            "severity": "HIGH",
            "explanation": (
                "The input contains an XML DOCTYPE that declares external entities. If the "
                "server's XML parser resolves them, the attacker can read local files or make "
                "the server send requests to internal systems."
            ),
            "what_attacker_gets": (
                "Contents of local files such as configuration and credentials, and a path "
                "to SSRF against internal services."
            ),
            "prevention": [
                "Disable DTDs and external entity resolution in the XML parser",
                "In Python, parse untrusted XML with defusedxml instead of the standard library parsers",
                "Prefer JSON for data exchange where XML features are not needed"
            ],
            "cwe": "CWE-611",
            "owasp": "A05:2021 - Security Misconfiguration"
        },
        'SSTI': {
            "attack_type": "Server-Side Template Injection (SSTI)",
            "severity": "CRITICAL",
            "explanation": (
                "The input contains template syntax such as {{ }} or ${ }. If the server "
                "renders user input as part of a template, the attacker's expression runs "
                "inside the template engine on the server."
            ),
            "what_attacker_gets": (
                "Often full remote code execution on the server through the template "
                "engine's access to the underlying language runtime."
            ),
            "prevention": [
                "Pass user input to templates only as data variables, never as part of the template source",
                "Use a sandboxed template environment (e.g. Jinja2 SandboxedEnvironment) if users must supply templates",
                "Reject or escape template delimiters in fields that are rendered"
            ],
            "cwe": "CWE-1336",
            "owasp": "A03:2021 - Injection"
        },
        'Hardcoded Credentials': {
            "attack_type": "Hard-coded Credentials",
            "severity": "HIGH",
            "explanation": (
                "The input contains what looks like a password, API key or secret written "
                "directly in code or a request. Anyone who can read the code, page source or "
                "logs can reuse it."
            ),
            "what_attacker_gets": (
                "Direct access to the account, database or third-party service the "
                "credential belongs to."
            ),
            "prevention": [
                "Revoke and rotate the exposed credential immediately",
                "Load secrets from environment variables or a secrets manager, never from source code",
                "Add a secret scanner (e.g. gitleaks) to pre-commit hooks and CI"
            ],
            "cwe": "CWE-798",
            "owasp": "A07:2021 - Identification and Authentication Failures"
        },
    }

    return FALLBACKS.get(ptype, {
        "attack_type": ptype or "Unknown Attack",
        "severity": "HIGH",
        "explanation": (
            "The scanner detected patterns consistent with a web attack in this input. "
            "The payload contains sequences that could be used to exploit the target application "
            "if not properly sanitised and validated."
        ),
        "what_attacker_gets": (
            "Potential unauthorised access, data leakage, or application compromise "
            "depending on how the server processes this input."
        ),
        "prevention": [
            "Validate and sanitise all user-supplied input on the server side",
            "Apply a Web Application Firewall (WAF) to filter malicious patterns",
            "Follow the OWASP Input Validation Cheat Sheet for your framework"
        ],
        "cwe":   patterns[0]['cwe']   if patterns else "CWE-20",
        "owasp": "A03:2021 - Injection"
    })
