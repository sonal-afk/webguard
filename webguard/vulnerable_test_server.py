import re
from flask import Flask, request
from markupsafe import escape
app = Flask(__name__)

@app.route('/')
def home():
    return '''
    <h2>WebGuard Test Server</h2>
    <p>Intentionally vulnerable demo target — used only to exercise WebGuard's
    guided scan workflow locally. Never expose this server publicly.</p>
    <ul>
        <li><a href="/sqli?id=1">SQL Injection Test</a></li>
        <li><a href="/xss?name=hello">XSS Test</a></li>
        <li><a href="/lfi?file=index.html">Path Traversal Test</a></li>
        <li><a href="/cmdi?host=127.0.0.1">Command Injection Test</a></li>
        <li><a href="/redirect?url=https://example.com">Open Redirect Test</a></li>
        <li><a href="/login">Login Form (SQLi/XSS via POST)</a></li>
        <li><a href="/safe?page=1">Safe Page</a></li>
    </ul>'''

@app.route('/sqli')
def sqli():
    uid = request.args.get('id', '')
    # Simulates what a real app that concatenates input into a SQL query
    # would do: an unescaped quote breaks the query and leaks a MySQL-style
    # syntax error. No real database is involved.
    if "'" in uid:
        return (
            "Warning: mysql_fetch_array(): supplied argument is not a valid MySQL result resource\n"
            f"You have an error in your SQL syntax; check the manual that corresponds to your MySQL "
            f"server version for the right syntax to use near '{uid}' at line 1"
        ), 500
    return f"User ID: {uid}"

@app.route('/xss')
def xss():
    return f"Hello {request.args.get('name','')}"

@app.route('/lfi')
def lfi():
    fname = request.args.get('file', '')
    # Simulates a vulnerable app that reads whatever path it's given —
    # leaks fake but realistic file content for traversal payloads. No real
    # file is ever read.
    if '..' in fname or '%2e%2e' in fname.lower():
        return (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "127.0.0.1 localhost\n"
            "::1 localhost\n"
            f"# (simulated leaked contents for path: {fname})"
        )
    return f"File: {fname}"

@app.route('/cmdi')
def cmdi():
    """
    Simulated command-injection endpoint. It never actually runs a shell —
    it just reflects the WebGuard marker if the input looks like a shell
    metacharacter injection followed by 'echo', the same way real vulnerable
    apps that shell out to `ping <host>` etc. would leak command output.
    """
    host = request.args.get('host', '')
    if re.search(r'[;|&`]+\s*echo\s+webguard_cmd_test', host):
        return f"Pinging {host.split(';')[0].split('|')[0].split('&')[0]} ...\nwebguard_cmd_test\n"
    return f"Pinging {host} ..."

@app.route('/redirect')
def redirect_page():
    dest = request.args.get('url', '')
    # Deliberately vulnerable: redirects to any user-supplied URL with no
    # allowlist/same-origin validation (classic open redirect, CWE-601).
    if dest:
        return '', 302, {'Location': dest}
    return "No redirect target specified."

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return '''
        <h2>Login</h2>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="username"><br>
            <input type="text" name="password" placeholder="password"><br>
            <button type="submit">Sign in</button>
        </form>'''
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    # Deliberately vulnerable: reflects input and "fails open" on a classic
    # SQLi auth-bypass string, for the guided scanner's form testing to find.
    if "' or '1'='1" in username.lower() or "' or '1'='1" in password.lower():
        return f"Welcome back, {username}! (login bypassed)"
    return f"Login failed for user: {username}"

@app.route('/safe')
def safe():
    # The one correctly-written endpoint: output is HTML-escaped, so it is a
    # true negative for the scanner to compare against.
    return f"Page {escape(request.args.get('page','1'))} - nothing suspicious here"

if __name__ == '__main__':
    app.run(port=9000)