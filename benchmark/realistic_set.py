# realistic_set.py
#
# A second, hand-written test set used when the pattern engine was revised
# (November 2026). The main benchmark (eval_set.csv) has two weaknesses for
# judging rule changes:
#
#   1. Its benign samples are very easy (plain "?page=3&sort=price" URLs),
#      so it cannot show whether a rule fires on realistic harmless input
#      such as an apostrophe in a name, a JavaScript template literal, a
#      jQuery call or a Python time.sleep().
#   2. The rule revision was guided by the errors the old rules made on
#      eval_set.csv, so eval_set.csv is no longer a blind test for the
#      pattern engine.
#
# This file therefore holds payloads and benign inputs that are NOT taken
# from eval_set.csv (different payload strings, different hosts, plus pasted
# code snippets). Run it with:  python benchmark/realistic_set.py
# It reports pattern-engine precision/recall on this set.
#
# Result with the rules before the revision: precision 0.676, recall 0.523
# (TP=23 FN=21 FP=11 TN=25). False alarms were mostly ordinary code: JS
# template literals, jQuery, time.sleep(), Jinja templates, regex .exec().

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "webguard"))

ATTACKS = [
    # (category, text)
    ("SQL Injection", "https://store.acme.io/product?pid=7' AND 1=2 UNION ALL SELECT null,version()-- -"),
    ("SQL Injection", "https://store.acme.io/product?pid=7 OR 2>1"),
    ("SQL Injection", "https://store.acme.io/product?pid=7'/**/oR/**/'a'='a"),
    ("SQL Injection", "https://store.acme.io/product?pid=7%27%20AND%20SLEEP(3)%23"),
    ("SQL Injection", "GET /orders?id=12\" HTTP/1.1\nHost: shop.acme.io\n"),
    ("SQL Injection", "https://store.acme.io/list?sort=name' ORDER BY 9--"),
    ("SQL Injection", "username=admin')-- &password=x"),
    ("SQL Injection", "https://store.acme.io/p?id=1 AND extractvalue(1,concat(0x7e,user()))"),
    ("XSS", "https://forum.acme.io/search?q=\"><svg/onload=alert(1)>"),
    ("XSS", "https://forum.acme.io/search?q=<img src=x onerror=prompt(document.domain)>"),
    ("XSS", "https://forum.acme.io/search?q=%253Cscript%253Ealert(1)%253C%252Fscript%253E"),
    ("XSS", "https://forum.acme.io/profile?bio=<details open ontoggle=alert(1)>"),
    ("XSS", "https://forum.acme.io/go?link=JaVaScRiPt:alert(1)"),
    ("XSS", "https://forum.acme.io/search?q=<i>hi</i>"),
    ("XSS", "comment=' autofocus onfocus='alert(1)"),
    ("XSS", "document.getElementById('out').innerHTML = location.hash.slice(1);"),
    ("Path Traversal", "https://files.acme.io/download?file=....//....//etc/hosts"),
    ("Path Traversal", "https://files.acme.io/download?file=..%5c..%5cwindows%5cwin.ini"),
    ("Path Traversal", "https://files.acme.io/view?doc=%252e%252e%252fconfig.php"),
    ("Path Traversal", "https://files.acme.io/view?page=/proc/self/environ"),
    ("Command Injection", "https://tools.acme.io/ping?host=8.8.8.8;id"),
    ("Command Injection", "https://tools.acme.io/ping?host=8.8.8.8|ping -c 3 attacker.example"),
    ("Command Injection", "https://tools.acme.io/ping?host=8.8.8.8%0Asleep%205"),
    ("Command Injection", "https://tools.acme.io/ping?host=`nslookup x.attacker.example`"),
    ("Command Injection", "https://tools.acme.io/ping?host=$(whoami)"),
    ("Command Injection", "host=127.0.0.1 && type C:\\Windows\\win.ini"),
    ("Command Injection", "subprocess.run(f\"ping {host}\", shell=True)"),
    ("SSRF", "https://img.acme.io/fetch?src=http://169.254.169.254/latest/meta-data/iam/"),
    ("SSRF", "https://img.acme.io/fetch?image=http://localhost:8080/admin"),
    ("SSRF", "https://img.acme.io/fetch?u=http://[::1]:22/"),
    ("SSRF", "https://img.acme.io/fetch?u=http://2130706433/"),
    ("SSRF", "https://img.acme.io/fetch?u=http://metadata.google.internal/computeMetadata/v1/"),
    ("Open Redirect", "https://login.acme.io/auth?return_url=https://acme-login.co/steal"),
    ("Open Redirect", "https://login.acme.io/auth?continue=//phish.example.net"),
    ("Open Redirect", "https://login.acme.io/auth?next=/\\phish.example.net"),
    ("Open Redirect", "https://login.acme.io/auth?redirect_uri=https%3A%2F%2Fphish.example.net%2F"),
    ("XXE", "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/hostname\">]><r>&x;</r>"),
    ("SSTI", "https://mail.acme.io/preview?name={{7*7}}"),
    ("SSTI", "https://mail.acme.io/preview?name={{ config.__class__.__init__.__globals__['os'].popen('id').read() }}"),
    ("SSTI", "https://mail.acme.io/preview?name=${7*7}"),
    ("SSTI", "https://mail.acme.io/preview?name=<#assign ex=\"freemarker.template.utility.Execute\"?new()>"),
    ("Hardcoded Credentials", "DB_PASSWORD = \"Tr0ub4dor&3\""),
    ("Hardcoded Credentials", "aws_key = 'AKIAIOSFODNN7EXAMPLE'"),
    ("Hardcoded Credentials", "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."),
]

BENIGN = [
    "https://store.acme.io/search?q=O'Brien",
    "https://store.acme.io/search?q=rock 'n' roll",
    "https://store.acme.io/search?q=don't stop",
    "https://store.acme.io/search?q=5' 10\" height chart",
    "https://store.acme.io/search?q=select a size",
    "https://store.acme.io/search?q=drop table lamp",
    "https://store.acme.io/search?q=cat food and dog food",
    "https://store.acme.io/search?q=1 < 2 math",
    "https://news.acme.io/article?id=42#comments",
    "https://news.acme.io/feed?from=2026-10-01&to=2026-10-31",
    "https://login.acme.io/auth?next=/dashboard",
    "https://login.acme.io/auth?next=https://login.acme.io/home",
    "https://login.acme.io/auth?return_to=https://www.acme.io/account",
    "https://api.acme.io/v1/items?fields=id,name,price&limit=50",
    "https://api.acme.io/v1/items?color=0x1F2937",
    "GET /api/users/15 HTTP/1.1\nHost: api.acme.io\nAuthorization: Bearer <token>\n",
    "POST /contact HTTP/1.1\nHost: www.acme.io\nContent-Type: application/x-www-form-urlencoded\n\nname=Ann Lee&msg=See you at 5 -- thanks!",
    "https://www.acme.io/docs/getting-started/install",
    "https://cdn.acme.io/assets/app.min.js?v=3.2.1",
    "https://www.acme.io/blog/why-we-moved-to-postgres",
    # pasted code snippets
    "const msg = `Hello ${user.name}, you have ${count} new messages`;",
    "$('#submit').on('click', function () { $(this).prop('disabled', true); });",
    "import time\nfor i in range(3):\n    time.sleep(2)\n    print(i)",
    "result = subprocess.run([\"git\", \"status\"], capture_output=True)",
    "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))",
    "stmt = conn.prepareStatement(\"SELECT * FROM orders WHERE id = ?\");",
    "<p>Hello {{ user.first_name }}, welcome back!</p>",
    "{% for item in cart %}<li>{{ item.name }}</li>{% endfor %}",
    "const re = /ab+c/; const m = re.exec(text);",
    "password = os.environ[\"DB_PASSWORD\"]",
    "if (a > b) { return a; } // pick larger",
    "<a href=\"/help\">Help</a> <button type=\"submit\">Save</button>",
    "SELECT name, email FROM customers WHERE created_at > '2026-01-01';",
    "ls -la && cd src",
    "echo \"build finished\"",
    "window.location.href = '/login';",
]


def evaluate(detect):
    tp = sum(1 for _, t in ATTACKS if detect(t))
    fn_items = [(c, t) for c, t in ATTACKS if not detect(t)]
    fp_items = [t for t in BENIGN if detect(t)]
    fp = len(fp_items)
    tn = len(BENIGN) - fp
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / len(ATTACKS)
    return tp, fp, tn, len(fn_items), precision, recall, fn_items, fp_items


if __name__ == "__main__":
    import backend as b  # noqa: E402

    def detect(text):
        return bool(b.detect_patterns(text))

    tp, fp, tn, fn, p, r, fn_items, fp_items = evaluate(detect)
    print(f"attacks={len(ATTACKS)} benign={len(BENIGN)}")
    print(f"TP={tp} FN={fn} FP={fp} TN={tn}  precision={p:.3f} recall={r:.3f}")
    print("\nMissed attacks:")
    for c, t in fn_items:
        print(f"  [{c}] {t[:90]!r}")
    print("\nFalse alarms on harmless input:")
    for t in fp_items:
        print(f"  {t[:90]!r}")
