# report_generator.py
# Generates a professional HTML penetration test report
# from active scan results. Open the returned HTML in a browser
# and use Print → Save as PDF.

from datetime import datetime
from html import escape


SEV_COLOR = {
    'CRITICAL': '#dc2626',
    'HIGH':     '#ea580c',
    'MEDIUM':   '#d97706',
    'LOW':      '#16a34a',
}

SEV_BG = {
    'CRITICAL': '#fef2f2',
    'HIGH':     '#fff7ed',
    'MEDIUM':   '#fffbeb',
    'LOW':      '#f0fdf4',
}


def _badge(sev):
    sev = escape(str(sev))
    c = SEV_COLOR.get(sev, '#6b7280')
    return (f'<span style="background:{c};color:#fff;font-size:10px;'
            f'padding:2px 10px;border-radius:4px;font-weight:700;'
            f'letter-spacing:1px;">{sev}</span>')


REVIEW_LABEL = {
    'confirmed':      ('&#10003; Confirmed by analyst', '#166534'),
    'false_positive': ('&#10005; Dismissed — false positive', '#6b7280'),
    'needs_review':   ('&#9888; Needs review — not yet verified', '#92400e'),
    'unreviewed':     ('&#9888; Not yet reviewed by an analyst', '#92400e'),
}


def _raw_exchange_block(f):
    """Collapsible raw request/response/context so the reader can manually
    verify a finding instead of trusting the scanner's verdict alone."""
    raw_req  = f.get('raw_request')
    raw_resp = f.get('raw_response')
    context  = f.get('context_snippet')
    if not (raw_req or raw_resp or context):
        return ''

    parts = []
    if raw_req:
        method = escape(str(raw_req.get('method', '')))
        url    = escape(str(raw_req.get('url', '')))
        params = escape(str(raw_req.get('params', '')))
        parts.append(
            f'<div class="lbl" style="width:auto;margin-bottom:4px;">Raw Request</div>'
            f'<pre class="raw-block">{method} {url}\nParams/Data: {params}</pre>'
        )
    if raw_resp:
        status = escape(str(raw_resp.get('status_code', '')))
        body   = escape(str(raw_resp.get('body_snippet', '')))
        parts.append(
            f'<div class="lbl" style="width:auto;margin-bottom:4px;">Raw Response</div>'
            f'<pre class="raw-block">HTTP {status}\n\n{body}</pre>'
        )
    if context:
        parts.append(
            f'<div class="lbl" style="width:auto;margin-bottom:4px;">Context Around Evidence</div>'
            f'<pre class="raw-block">{escape(str(context))}</pre>'
        )

    return f'''
        <details class="raw-exchange">
            <summary>Show raw request / response (for manual verification)</summary>
            {''.join(parts)}
        </details>'''


def _finding_block(i, f):
    sev    = str(f.get('severity', 'MEDIUM'))
    border = SEV_COLOR.get(sev, '#6b7280')
    bg     = SEV_BG.get(sev, '#fff')

    url    = escape(str(f.get('url', 'Unknown URL')))
    vector = escape(str(f.get('vector', 'URL Parameter')))
    p_name = escape(str(f.get('payload_name', 'Manual Probe')))
    payload = escape(str(f.get('payload', '')))
    param = escape(str(f.get('param', '')))
    evidence = escape(str(f.get('evidence', 'returning unexpected data')))
    finding_type = escape(str(f.get('type', 'Unknown')))
    cwe = escape(str(f.get('cwe', '-')))
    owasp = escape(str(f.get('owasp', '')))

    how = (
        f'The scanner injected the <strong>{p_name}</strong> payload '
        f'<code>{payload}</code> into the '
        f'<code>{param}</code> parameter '
        f'via <strong>{vector}</strong> at <code>{url}</code>. '
        f'The server response confirmed the vulnerability by: '
        f'{evidence.lower()}.'
    )

    review_status = f.get('review_status', 'unreviewed' if 'confirmed' not in f else None)
    if review_status:
        review_text, review_color = REVIEW_LABEL.get(review_status, REVIEW_LABEL['unreviewed'])
    else:
        # Legacy findings from the old full-auto scanner only had a boolean 'confirmed'
        review_text = '&#10003; Yes — vulnerability confirmed by server response' if f.get('confirmed') else '&#9888; Suspected'
        review_color = '#166534' if f.get('confirmed') else '#92400e'
    review_note = escape(str(f.get('review_note', '')))

    # Always-visible copy-paste reproduction line (must survive PDF export, so
    # it lives outside the collapsible raw-exchange block below).
    curl_cmd = f.get('curl_command')
    curl_block = (
        f'<div style="margin-top:12px;">'
        f'<div class="how-label" style="color:#475569;font-size:10px;margin-bottom:4px;">REPRODUCE THIS FINDING (curl)</div>'
        f'<pre class="raw-block" style="max-height:none;">{escape(str(curl_cmd))}</pre>'
        f'</div>'
    ) if curl_cmd else ''

    return f'''
    <div class="finding" style="border-left:4px solid {border};background:{bg};">
        <div class="finding-head" style="border-bottom:1px solid #e5e7eb;">
            <span class="finding-title">Finding #{i} &mdash; {finding_type}</span>
            {_badge(sev)}
        </div>
        <div class="finding-body">
            <table class="detail-table">
                <tr><td class="lbl">Source URL</td>
                    <td><code style="word-break:break-all;">{url}</code></td></tr>
                <tr><td class="lbl">Injected Vector</td>
                    <td><strong>{vector}</strong> / <code class="code-pill">{param or "-"}</code></td></tr>
                <tr><td class="lbl">CWE</td>
                    <td><strong>{cwe}</strong></td></tr>
                {f'<tr><td class="lbl">OWASP Top 10</td><td><strong>{owasp}</strong></td></tr>' if owasp else ''}
                <tr><td class="lbl">Payload Used</td>
                    <td>
                        <div style="font-size:11px;font-weight:700;color:#ef4444;margin-bottom:4px;">{p_name.upper()}</div>
                        <code class="code-danger" style="font-size:14px;padding:8px 12px;border:1px solid #fee2e2;">{payload or "-"}</code>
                    </td></tr>
                <tr><td class="lbl">Evidence</td>
                    <td style="color:#92400e;font-weight:500;">{evidence or "-"}</td></tr>
                <tr><td class="lbl">Analyst Review</td>
                    <td style="color:{review_color};font-weight:600;">{review_text}{f' &mdash; <span style="font-weight:400;color:#6b7280;">{review_note}</span>' if review_note else ''}</td></tr>
            </table>
            {curl_block}
            {_raw_exchange_block(f)}
        </div>
        <div class="how-tested" style="background:#f8fafc;border-top:1px solid #e2e8f0;">
            <div class="how-label" style="color:#475569;font-size:10px;margin-bottom:6px;">PENETRATION DETAILS</div>
            <p style="font-size:12.5px;color:#334155;">{how}</p>
        </div>
    </div>'''


def generate_report(scan_data: dict) -> str:
    target   = escape(str(scan_data.get('target', 'Unknown')))
    findings = scan_data.get('findings', [])
    scanned  = scan_data.get('scanned', [])
    summary  = scan_data.get('summary', {})
    ts       = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # ── Severity boxes ──
    sev_boxes = ''
    for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = summary.get('by_severity', {}).get(s, 0)
        c = SEV_COLOR[s]
        sev_boxes += (
            f'<div class="sev-box" style="border-top:3px solid {c};">'
            f'<div class="sev-num" style="color:{c};">{count}</div>'
            f'<div class="sev-lbl">{s}</div></div>'
        )

    # ── Findings ──
    if findings:
        findings_html = ''.join(_finding_block(i, f) for i, f in enumerate(findings, 1))
    else:
        findings_html = '''
        <div class="no-findings">
            <div style="font-size:28px;margin-bottom:8px;">&#10003;</div>
            <strong>No vulnerabilities confirmed during active scan.</strong>
            <p>All tested parameters responded safely to attack payloads.</p>
        </div>'''

    # ── Scanned pages ──
    scanned_rows = ''.join(
        f'<tr><td class="scan-row">'
        f'{"&#128279; " if "FORM:" not in s else "&#128203; "}{escape(str(s))}'
        f'</td></tr>'
        for s in scanned
    )

    overall       = 'VULNERABLE' if findings else 'SECURE'
    overall_icon  = '&#128680;' if findings else '&#9989;'
    overall_color = '#dc2626' if findings else '#166534'
    overall_bg    = '#fef2f2' if findings else '#f0fdf4'
    vuln_count    = len(findings)
    pages_count   = summary.get('pages_scanned', 0)

    # ── Header text ──
    scan_method = scan_data.get('scan_method', 'active')
    # 'guided' and 'active' are both payload-injection scans; only an explicit
    # 'static' method is the pattern/ML path. Anything not 'static' is active.
    is_active = scan_method != 'static'
    method_title = "Active Penetration Test" if is_active else "Static Code Analysis"
    method_desc = "(automated payload injection)" if is_active else "(pattern & ML-based analysis)"

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>WebGuard Report &mdash; {target}</title>
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family:"Segoe UI",Arial,sans-serif; color:#111; background:#fff; font-size:14px; line-height:1.6; }}
  .page {{ max-width:920px; margin:0 auto; padding:44px 44px; }}
  h2 {{ font-size:15px; font-weight:700; color:#374151; margin:32px 0 14px;
        padding-bottom:6px; border-bottom:2px solid #e5e7eb; letter-spacing:.5px; }}
  code {{ font-family:"Courier New",monospace; font-size:12px; }}
  table {{ width:100%; border-collapse:collapse; }}

  /* header */
  .report-header {{ display:flex; justify-content:space-between; align-items:flex-start;
                    padding-bottom:24px; border-bottom:3px solid #111; margin-bottom:28px; }}
  .report-title {{ font-size:26px; font-weight:800; }}
  .report-meta  {{ text-align:right; font-size:12px; color:#6b7280; line-height:1.9; }}

  /* overall */
  .overall {{ display:flex; align-items:center; gap:16px; padding:18px 24px;
              border-radius:10px; margin-bottom:28px; }}
  .overall-icon  {{ font-size:34px; }}
  .overall-title {{ font-size:18px; font-weight:800; }}
  .overall-sub   {{ font-size:13px; color:#6b7280; margin-top:2px; }}

  /* target table */
  .target-table td {{ padding:10px 14px; border-bottom:1px solid #e5e7eb; font-size:13px; }}
  .target-table tr:last-child td {{ border-bottom:none; }}
  .target-table td:first-child {{ font-weight:600; width:200px; background:#f9fafb; }}

  /* severity boxes */
  .sev-row {{ display:flex; gap:12px; margin-bottom:8px; }}
  .sev-box {{ flex:1; text-align:center; padding:16px 8px; background:#fff;
              border:1px solid #e5e7eb; border-radius:8px; }}
  .sev-num {{ font-size:28px; font-weight:800; line-height:1; }}
  .sev-lbl {{ font-size:11px; color:#6b7280; margin-top:4px; letter-spacing:1px; }}

  /* findings */
  .finding {{ border:1px solid #e5e7eb; border-radius:8px; margin-bottom:20px; overflow:hidden; }}
  .finding-head {{ display:flex; justify-content:space-between; align-items:center;
                   padding:12px 18px; }}
  .finding-title {{ font-size:15px; font-weight:700; }}
  .finding-body  {{ padding:14px 18px; }}
  .detail-table td {{ padding:6px 0; font-size:13px; vertical-align:top; }}
  .lbl {{ color:#6b7280; width:160px; }}
  .code-pill   {{ background:#f3f4f6; padding:2px 6px; border-radius:4px; }}
  .code-danger {{ background:#fef2f2; color:#dc2626; padding:4px 8px;
                  border-radius:4px; display:block; word-break:break-all; margin-top:4px; }}
  .how-tested {{ padding:12px 18px; background:#f9fafb; border-top:1px solid #e5e7eb; font-size:12px; }}
  .how-label  {{ font-weight:700; color:#374151; margin-bottom:4px; letter-spacing:.5px; }}
  .how-tested p {{ color:#6b7280; line-height:1.7; }}

  /* raw request/response — manual verification aid */
  .raw-exchange {{ margin-top:10px; }}
  .raw-exchange summary {{ cursor:pointer; font-size:11.5px; font-weight:600; color:#2563eb; }}
  .raw-block {{ background:#0f172a; color:#d1d5db; font-size:11px; padding:10px 12px;
                border-radius:6px; margin:6px 0 10px; white-space:pre-wrap; word-break:break-all;
                max-height:220px; overflow-y:auto; }}

  /* no findings */
  .no-findings {{ background:#f0fdf4; border:1px solid #86efac; border-radius:8px;
                  padding:24px; text-align:center; color:#166534; font-size:13px; }}
  .no-findings p {{ margin-top:6px; color:#6b7280; }}

  /* methodology */
  .method-box {{ background:#f9fafb; border:1px solid #e5e7eb; border-radius:8px;
                 padding:18px; font-size:13px; }}
  .method-box ol {{ padding-left:20px; color:#374151; line-height:2; }}
  .method-box .note {{ margin-top:12px; color:#6b7280; }}

  /* scanned */
  .scan-row {{ padding:7px 10px; border-bottom:1px solid #f3f4f6; font-size:12px;
               font-family:"Courier New",monospace; word-break:break-all; }}

  /* disclaimer */
  .disclaimer {{ margin-top:32px; padding:14px 18px; background:#fefce8;
                 border:1px solid #fde047; border-radius:8px; font-size:12px; color:#713f12; }}

  /* print button */
  .print-bar {{ margin-top:28px; text-align:center; }}
  .btn-print {{ background:#111; color:#fff; border:none; padding:12px 32px;
                border-radius:8px; font-size:14px; font-weight:600; cursor:pointer; margin-right:10px; }}
  .btn-close {{ background:#f3f4f6; color:#374151; border:1px solid #e5e7eb;
                padding:12px 24px; border-radius:8px; font-size:14px; cursor:pointer; }}

  @media print {{
    .print-bar {{ display:none; }}
    body {{ font-size:12px; }}
    .page {{ padding:20px; }}
  }}
</style>
</head>
<body>
<div class="page">

  <!-- Header -->
  <div class="report-header">
    <div>
      <div style="font-size:11px;letter-spacing:2px;color:#6b7280;text-transform:uppercase;margin-bottom:6px;">
        WebGuard Security Scanner
      </div>
      <div class="report-title">Penetration Test Report</div>
      <div style="margin-top:6px;color:#6b7280;font-size:13px;">
        Active vulnerability assessment with payload verification
      </div>
    </div>
    <div class="report-meta">
      <div><strong>Date:</strong> {ts}</div>
      <div><strong>Scanner:</strong> WebGuard v1.0</div>
      <div><strong>Method:</strong> Active Black-Box Pentest</div>
    </div>
  </div>

  <!-- Overall -->
  <div class="overall" style="background:{overall_bg};border:2px solid {overall_color};">
    <div class="overall-icon">{overall_icon}</div>
    <div>
      <div class="overall-title" style="color:{overall_color};">
        Overall Assessment: {overall}
      </div>
      <div class="overall-sub">
        {vuln_count} confirmed {"vulnerabilities" if vuln_count != 1 else "vulnerability"} found
        across {pages_count} pages/endpoints scanned
      </div>
    </div>
  </div>

  <!-- 1. Target Info -->
  <h2>1. Target Information</h2>
  <table class="target-table" style="border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;">
    <tr><td>Target URL</td><td><code>{target}</code></td></tr>
    <tr><td>Scan Type</td><td>{method_title} {method_desc}</td></tr>
    <tr><td>Tests Performed</td>
        <td>{("SQL Injection (Error-Based &amp; Time-Based), Reflected XSS, Path Traversal, Command Injection, Open Redirect" if is_active else "Regex Pattern Matching, CodeBERT ML Vulnerability Detection")}</td></tr>
    <tr><td>Endpoints Tested</td><td>{pages_count} {"pages / forms" if is_active else "direct input"}</td></tr>
  </table>

  <!-- 2. Severity Summary -->
  <h2>2. Severity Summary</h2>
  <div class="sev-row">{sev_boxes}</div>

  <!-- 3. Findings -->
  <h2>3. Confirmed Vulnerabilities</h2>
  {findings_html}

  <!-- 4. Methodology -->
  <h2>4. Testing Methodology</h2>
  <div class="method-box">
    <p style="margin-bottom:10px;">
      WebGuard performed an active black-box penetration test. The scanner executed the following steps:
    </p>
    <ol>
      <li>Confirmed the target host was on the tester's authorized-targets allowlist before any request was sent</li>
      <li>Fetched the target page and recorded baseline response time and content (recon only — no payloads)</li>
      <li>Extracted all URL parameters, HTML form fields, and linked pages with query strings, and presented them to the analyst</li>
      <li>Injected only the vulnerability classes and endpoints the analyst explicitly selected</li>
      <li>Analysed server responses for SQL error messages, reflected payloads, unusual time delays, leaked file content, and command-output markers</li>
      <li>Captured the raw request and response for every finding so the analyst could manually verify it before relying on it</li>
      <li>Only includes findings the server response <strong>confirmed</strong> with concrete evidence; final Confirmed/False Positive status reflects the analyst's manual review, not just the automated match</li>
    </ol>
    <p class="note">
      User-Agent used: <code>WebGuard-Scanner/1.0 (Educational Security Scanner)</code><br>
      Automated results are a starting point, not proof — verify unfamiliar findings against the live page, request, and response yourself before acting on them.
    </p>
  </div>

  <!-- 5. Scanned Pages -->
  <h2>5. Pages and Endpoints Scanned</h2>
  <table style="border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;">
    <tr style="background:#f9fafb;">
      <td style="padding:8px 10px;border-bottom:1px solid #e5e7eb;font-size:12px;font-weight:600;">Endpoint / Form</td>
    </tr>
    {scanned_rows}
  </table>

  <!-- Disclaimer -->
  <div class="disclaimer">
    <strong>&#9888; Legal Disclaimer:</strong> This report was generated by WebGuard for
    educational and authorised security testing purposes only. Only scan systems you own or
    have explicit written permission to test. Unauthorised penetration testing is illegal under
    the Computer Misuse Act 1990 and equivalent legislation worldwide.
  </div>

  <!-- Print -->
  <div class="print-bar">
    <button class="btn-print" onclick="window.print()">&#128424; Print / Save as PDF</button>
    <button class="btn-close" onclick="window.close()">Close</button>
  </div>

</div>
</body>
</html>'''
