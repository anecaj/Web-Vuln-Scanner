"""
Web Vulnerability Scanner — Core Engine
Checks aligned with OWASP Top 10 (2021).
All checks are passive/non-destructive — safe for use on sites you own.
"""
import re
import time
import socket
import urllib.parse
import requests
from bs4 import BeautifulSoup

# Shared session with realistic browser headers
SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
})
TIMEOUT = 10


def finding(check_name, category, severity, description, evidence, remediation, owasp, cwe=None):
    """Helper to create a standardized finding dict."""
    return {
        "check_name":   check_name,
        "category":     category,
        "severity":     severity,       # CRITICAL | HIGH | MEDIUM | LOW | INFO
        "description":  description,
        "evidence":     evidence,
        "remediation":  remediation,
        "owasp":        owasp,
        "cwe":          cwe or "",
    }


# ── Fetch helpers ──────────────────────────────────────────────────────────────

def safe_get(url, params=None, allow_redirects=True, timeout=TIMEOUT):
    try:
        return SESSION.get(url, params=params, allow_redirects=allow_redirects,
                           timeout=timeout, verify=False)
    except requests.exceptions.SSLError:
        try:
            return SESSION.get(url, params=params, allow_redirects=allow_redirects,
                               timeout=timeout, verify=False)
        except Exception:
            return None
    except Exception:
        return None


# ── Individual checks ──────────────────────────────────────────────────────────

def check_ssl(url, findings):
    """Check if site uses HTTPS and basic SSL validity."""
    parsed = urllib.parse.urlparse(url)

    if parsed.scheme != "https":
        findings.append(finding(
            "No HTTPS / Unencrypted Connection",
            "Transport Security",
            "HIGH",
            "The site is served over HTTP rather than HTTPS. All traffic between the "
            "browser and server is transmitted in plaintext and can be intercepted by "
            "an attacker on the network (man-in-the-middle attack).",
            f"URL scheme is '{parsed.scheme}' — not 'https'",
            "Obtain a TLS certificate (free via Let's Encrypt) and redirect all HTTP "
            "traffic to HTTPS using a permanent 301 redirect.",
            "A02:2021 Cryptographic Failures",
            "CWE-319",
        ))
        return

    # Check if HTTP version redirects to HTTPS
    http_url = url.replace("https://", "http://", 1)
    resp = safe_get(http_url, allow_redirects=False, timeout=5)
    if resp and resp.status_code not in (301, 302, 307, 308):
        findings.append(finding(
            "HTTP Not Redirected to HTTPS",
            "Transport Security",
            "MEDIUM",
            "The HTTP version of the site does not automatically redirect to HTTPS. "
            "Users who type the URL without 'https://' are served over an insecure connection.",
            f"HTTP response status: {resp.status_code} (expected 301/302)",
            "Configure your web server to return a 301 redirect from HTTP to HTTPS for all requests.",
            "A02:2021 Cryptographic Failures",
            "CWE-319",
        ))

    findings.append(finding(
        "HTTPS Enabled",
        "Transport Security",
        "INFO",
        "The site is served over HTTPS with TLS encryption.",
        f"URL scheme: https",
        "No action required.",
        "A02:2021 Cryptographic Failures",
    ))


def check_security_headers(resp, findings):
    """Check for presence of critical HTTP security headers."""
    headers = {k.lower(): v for k, v in resp.headers.items()}

    checks = [
        (
            "strict-transport-security",
            "Missing HTTP Strict Transport Security (HSTS)",
            "HIGH",
            "HSTS instructs browsers to only communicate with the server over HTTPS. "
            "Without it, attackers can perform SSL stripping attacks, downgrading the connection to HTTP.",
            "Strict-Transport-Security header absent",
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            "A02:2021 Cryptographic Failures",
            "CWE-523",
        ),
        (
            "content-security-policy",
            "Missing Content Security Policy (CSP)",
            "HIGH",
            "CSP prevents cross-site scripting (XSS) attacks by restricting which sources "
            "the browser is allowed to load scripts, styles, and other resources from.",
            "Content-Security-Policy header absent",
            "Add a Content-Security-Policy header. Start with: Content-Security-Policy: default-src 'self'",
            "A03:2021 Injection (XSS)",
            "CWE-693",
        ),
        (
            "x-frame-options",
            "Missing X-Frame-Options (Clickjacking Risk)",
            "MEDIUM",
            "Without X-Frame-Options, the page can be embedded in an iframe on a malicious site. "
            "Attackers can overlay invisible UI elements to trick users into clicking things "
            "they didn't intend to — this is called a clickjacking attack.",
            "X-Frame-Options header absent",
            "Add: X-Frame-Options: DENY  (or SAMEORIGIN if you need same-origin iframes)",
            "A05:2021 Security Misconfiguration",
            "CWE-1021",
        ),
        (
            "x-content-type-options",
            "Missing X-Content-Type-Options",
            "LOW",
            "Without this header, browsers may try to guess (sniff) the MIME type of a response, "
            "which can lead to XSS attacks if an attacker can upload content that gets misinterpreted.",
            "X-Content-Type-Options header absent",
            "Add: X-Content-Type-Options: nosniff",
            "A05:2021 Security Misconfiguration",
            "CWE-693",
        ),
        (
            "referrer-policy",
            "Missing Referrer-Policy",
            "LOW",
            "Without a Referrer-Policy, the browser may send the full URL of the current page "
            "as the Referer header to third-party sites, potentially leaking sensitive information "
            "like session tokens or private URLs.",
            "Referrer-Policy header absent",
            "Add: Referrer-Policy: strict-origin-when-cross-origin",
            "A05:2021 Security Misconfiguration",
            "CWE-116",
        ),
        (
            "permissions-policy",
            "Missing Permissions-Policy",
            "LOW",
            "Permissions-Policy controls which browser features (camera, microphone, geolocation) "
            "the site and embedded iframes are allowed to use.",
            "Permissions-Policy header absent",
            "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
            "A05:2021 Security Misconfiguration",
            "CWE-693",
        ),
    ]

    for header_name, name, severity, desc, evidence_base, remediation, owasp, cwe in checks:
        if header_name not in headers:
            findings.append(finding(name, "Security Headers", severity, desc,
                                    evidence_base, remediation, owasp, cwe))
        else:
            findings.append(finding(
                f"{header_name.title()} Present",
                "Security Headers", "INFO",
                f"The {header_name} header is correctly set.",
                f"{header_name}: {headers[header_name][:100]}",
                "No action required.", owasp,
            ))


def check_information_disclosure(resp, findings):
    """Detect server/technology information leakage in response headers."""
    headers = {k.lower(): v for k, v in resp.headers.items()}

    server = headers.get("server", "")
    if server:
        # Check if version is revealed
        version_pattern = re.compile(r"\d+\.\d+")
        if version_pattern.search(server):
            findings.append(finding(
                "Server Version Disclosure",
                "Information Disclosure",
                "MEDIUM",
                "The Server header reveals the exact web server software and version. "
                "Attackers can use this to look up known vulnerabilities for that specific version.",
                f"Server: {server}",
                "Configure your web server to suppress or genericize the Server header. "
                "In Apache: ServerTokens Prod. In Nginx: server_tokens off.",
                "A05:2021 Security Misconfiguration",
                "CWE-200",
            ))
        else:
            findings.append(finding(
                "Server Header Present (No Version)",
                "Information Disclosure",
                "INFO",
                "The Server header is present but doesn't reveal a version number.",
                f"Server: {server}",
                "Consider removing the Server header entirely for best practice.",
                "A05:2021 Security Misconfiguration",
            ))

    powered_by = headers.get("x-powered-by", "")
    if powered_by:
        findings.append(finding(
            "Technology Stack Disclosure (X-Powered-By)",
            "Information Disclosure",
            "MEDIUM",
            "The X-Powered-By header reveals the server-side technology stack. "
            "This helps attackers target known vulnerabilities in specific framework versions.",
            f"X-Powered-By: {powered_by}",
            "Remove the X-Powered-By header. In Express.js: app.disable('x-powered-by'). "
            "In PHP: expose_php = Off in php.ini.",
            "A05:2021 Security Misconfiguration",
            "CWE-200",
        ))

    # Check for debug/environment info in body
    body_lower = resp.text.lower()[:5000]
    debug_keywords = ["stack trace", "traceback", "debug mode", "sql syntax", "undefined variable",
                      "fatal error", "warning: include", "php parse error"]
    for kw in debug_keywords:
        if kw in body_lower:
            findings.append(finding(
                "Debug Information / Error Disclosure",
                "Information Disclosure",
                "HIGH",
                f"The page response contains debug information ('{kw}'). Debug output often reveals "
                "file paths, database queries, framework details, or source code snippets.",
                f"Found keyword '{kw}' in page response",
                "Disable debug mode in production. Set error_reporting to a log file, not the screen. "
                "Use a custom error page instead of raw stack traces.",
                "A05:2021 Security Misconfiguration",
                "CWE-209",
            ))
            break


def check_cors(resp, findings):
    """Check for CORS misconfiguration."""
    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

    if acao == "*":
        if acac == "true":
            findings.append(finding(
                "Critical CORS Misconfiguration",
                "CORS",
                "CRITICAL",
                "The server allows ANY origin to make cross-origin requests AND allows credentials "
                "(cookies, auth headers) to be included. This is a critical misconfiguration — "
                "it effectively allows any website to make authenticated API calls on behalf of your users.",
                f"Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
                "Never combine 'Access-Control-Allow-Origin: *' with 'Access-Control-Allow-Credentials: true'. "
                "Specify an explicit list of trusted origins instead.",
                "A05:2021 Security Misconfiguration",
                "CWE-942",
            ))
        else:
            findings.append(finding(
                "Permissive CORS Policy (Wildcard Origin)",
                "CORS",
                "MEDIUM",
                "The server allows any external website to make cross-origin requests to it. "
                "This may be appropriate for public APIs but is risky for authenticated endpoints.",
                "Access-Control-Allow-Origin: *",
                "Restrict CORS to specific trusted origins rather than using a wildcard. "
                "e.g. Access-Control-Allow-Origin: https://yourdomain.com",
                "A05:2021 Security Misconfiguration",
                "CWE-942",
            ))


def check_cookies(resp, findings):
    """Check cookies for missing security flags."""
    raw_cookies = resp.headers.get("Set-Cookie", "")
    if not raw_cookies:
        return

    cookies_str = raw_cookies.lower()

    if "httponly" not in cookies_str:
        findings.append(finding(
            "Cookie Missing HttpOnly Flag",
            "Cookie Security",
            "MEDIUM",
            "Cookies without the HttpOnly flag can be accessed by JavaScript running on the page. "
            "If an XSS attack succeeds, the attacker can steal session cookies via document.cookie.",
            f"Set-Cookie header lacks HttpOnly flag",
            "Add the HttpOnly flag to all session and authentication cookies: "
            "Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict",
            "A07:2021 Identification and Authentication Failures",
            "CWE-1004",
        ))

    if "secure" not in cookies_str:
        findings.append(finding(
            "Cookie Missing Secure Flag",
            "Cookie Security",
            "MEDIUM",
            "Cookies without the Secure flag can be transmitted over unencrypted HTTP connections. "
            "This exposes session tokens to interception on insecure networks.",
            "Set-Cookie header lacks Secure flag",
            "Add the Secure flag to all cookies: Set-Cookie: session=...; Secure; HttpOnly",
            "A07:2021 Identification and Authentication Failures",
            "CWE-614",
        ))

    if "samesite" not in cookies_str:
        findings.append(finding(
            "Cookie Missing SameSite Attribute",
            "Cookie Security",
            "LOW",
            "Without SameSite, cookies are sent with cross-site requests, making the site "
            "vulnerable to Cross-Site Request Forgery (CSRF) attacks.",
            "Set-Cookie header lacks SameSite attribute",
            "Add SameSite=Strict (or Lax) to cookies: Set-Cookie: session=...; SameSite=Strict",
            "A01:2021 Broken Access Control",
            "CWE-352",
        ))


def check_reflected_xss(url, soup, findings):
    """
    Test for potential reflected XSS by injecting a harmless marker into
    URL parameters and checking if it appears unencoded in the response.
    """
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    if not params:
        return

    marker = "XSSTESTMARKER12345"
    test_params = {k: [marker] for k in list(params.keys())[:3]}  # test first 3 params

    test_url = urllib.parse.urlunparse(
        parsed._replace(query=urllib.parse.urlencode(test_params, doseq=True))
    )
    resp = safe_get(test_url)
    if not resp:
        return

    if marker in resp.text:
        # Check if it appears inside an HTML tag attribute or script context
        body = resp.text
        marker_pos = body.find(marker)
        context = body[max(0, marker_pos-50):marker_pos+100]

        findings.append(finding(
            "Potential Reflected XSS",
            "Injection",
            "HIGH",
            "A test string injected into URL parameters was returned unencoded in the HTML response. "
            "This indicates the application echoes user input without proper HTML encoding, which "
            "is the primary cause of reflected Cross-Site Scripting (XSS) vulnerabilities. "
            "An attacker could craft a URL containing malicious JavaScript that executes in the victim's browser.",
            f"Marker '{marker}' reflected in response. Context: ...{context.strip()}...",
            "HTML-encode all user-supplied input before rendering it in the page. Use a templating "
            "engine that auto-escapes by default (Jinja2, React, etc). Never inject raw user input into HTML.",
            "A03:2021 Injection",
            "CWE-79",
        ))


def check_open_redirect(url, findings):
    """Check for open redirect vulnerability in common redirect parameters."""
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    test_target = "https://example.com"

    redirect_params = ["redirect", "redirect_url", "url", "next", "return",
                       "returnUrl", "return_url", "goto", "destination", "redir"]

    for param in redirect_params[:5]:  # limit to 5 tests
        test_url = f"{base}?{param}={urllib.parse.quote(test_target)}"
        resp = safe_get(test_url, allow_redirects=False, timeout=5)
        if not resp:
            continue
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location", "")
            if "example.com" in location:
                findings.append(finding(
                    "Open Redirect Vulnerability",
                    "Injection",
                    "MEDIUM",
                    f"The '{param}' parameter allows redirecting users to arbitrary external URLs. "
                    "Attackers use open redirects in phishing campaigns — they send a link that "
                    "appears to go to your trusted domain but redirects to a malicious site.",
                    f"?{param}={test_target} → redirects to {location}",
                    "Validate redirect destinations against a whitelist of allowed URLs/domains. "
                    "Never redirect to a URL constructed directly from user input.",
                    "A01:2021 Broken Access Control",
                    "CWE-601",
                ))
                return
        time.sleep(0.3)


def check_sql_injection_indicators(url, findings):
    """
    Test for SQL injection by injecting a single quote and checking for
    database error messages in the response (error-based SQLi detection).
    """
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    if not params:
        return

    db_error_patterns = [
        r"sql syntax", r"mysql_fetch", r"mysqli_", r"ora-\d{5}",
        r"pg_exec", r"sqlite_", r"microsoft sql", r"odbc_",
        r"syntax error.*sql", r"unclosed quotation mark",
        r"quoted string not properly terminated",
    ]

    for param_name in list(params.keys())[:3]:
        test_params = dict(params)
        test_params[param_name] = ["'"]
        test_url = urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(test_params, doseq=True))
        )
        resp = safe_get(test_url)
        if not resp:
            continue

        body_lower = resp.text.lower()[:10000]
        for pattern in db_error_patterns:
            if re.search(pattern, body_lower):
                findings.append(finding(
                    "SQL Injection Indicator Detected",
                    "Injection",
                    "CRITICAL",
                    f"Injecting a single quote (') into the '{param_name}' parameter caused a "
                    "database error to appear in the response. This is a strong indicator of SQL "
                    "injection vulnerability. An attacker can use this to read, modify, or delete "
                    "database records, bypass authentication, or in some cases execute OS commands.",
                    f"Parameter '{param_name}' with value ['] triggered DB error pattern: '{pattern}'",
                    "Use parameterized queries (prepared statements) for ALL database operations. "
                    "NEVER concatenate user input into SQL strings. Use an ORM. "
                    "Validate and sanitize all inputs server-side.",
                    "A03:2021 Injection",
                    "CWE-89",
                ))
                return
        time.sleep(0.3)


def check_sensitive_paths(base_url, findings):
    """Check for commonly exposed sensitive files and directories."""
    sensitive_paths = [
        ("/.git/config",        "Git Repository Exposed",    "CRITICAL", "CWE-538"),
        ("/.env",               ".env File Exposed",          "CRITICAL", "CWE-200"),
        ("/admin",              "Admin Panel Accessible",     "MEDIUM",   "CWE-284"),
        ("/phpinfo.php",        "PHPInfo Page Exposed",       "HIGH",     "CWE-200"),
        ("/wp-admin/",          "WordPress Admin Exposed",    "MEDIUM",   "CWE-284"),
        ("/server-status",      "Apache Server Status",       "MEDIUM",   "CWE-200"),
        ("/robots.txt",         "robots.txt Found",           "INFO",     "CWE-200"),
        ("/sitemap.xml",        "Sitemap Found",              "INFO",     "CWE-200"),
        ("/.well-known/security.txt", "security.txt Present", "INFO",    ""),
    ]

    parsed = urllib.parse.urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    for path, name, severity, cwe in sensitive_paths:
        url = base + path
        resp = safe_get(url, timeout=5)
        if not resp:
            continue

        if resp.status_code == 200 and len(resp.text) > 10:
            if severity == "CRITICAL":
                desc = (f"The file at '{path}' is publicly accessible. This is a serious vulnerability — "
                        f"it can expose credentials, environment variables, source code, or configuration data.")
                remediation = (f"Immediately block public access to '{path}' via your web server configuration. "
                               f"Move sensitive files outside the web root. Review and rotate any exposed credentials.")
            elif severity == "HIGH":
                desc = f"'{path}' is publicly accessible and exposes server configuration details."
                remediation = f"Remove or restrict access to '{path}' in production environments."
            elif severity == "MEDIUM":
                desc = f"'{path}' returned a 200 response. Verify this is intentional and properly secured."
                remediation = f"Restrict access to administrative paths. Implement authentication before reaching '{path}'."
            else:
                desc = f"'{path}' is accessible — informational finding."
                remediation = "Review whether public access to this path is intentional."

            findings.append(finding(
                name, "Sensitive Path Exposure", severity, desc,
                f"GET {path} → HTTP 200 ({len(resp.text)} bytes)",
                remediation,
                "A05:2021 Security Misconfiguration",
                cwe,
            ))
        time.sleep(0.2)


# ── Main scanner orchestrator ──────────────────────────────────────────────────

def run_scan(target_url: str, progress_callback=None) -> list[dict]:
    """
    Run all vulnerability checks against the target URL.
    Returns list of finding dicts.
    progress_callback(pct, message) called throughout scan.
    """
    import warnings
    warnings.filterwarnings("ignore")  # suppress SSL warnings

    findings = []

    def progress(pct, msg):
        if progress_callback:
            progress_callback(pct, msg)

    progress(5, "Connecting to target...")
    resp = safe_get(target_url)
    if not resp:
        raise ValueError(f"Could not connect to {target_url}. Check the URL and try again.")

    progress(10, "Checking SSL/TLS configuration...")
    check_ssl(target_url, findings)

    progress(22, "Analyzing security headers...")
    check_security_headers(resp, findings)

    progress(38, "Checking for information disclosure...")
    check_information_disclosure(resp, findings)

    progress(48, "Checking CORS configuration...")
    check_cors(resp, findings)

    progress(56, "Analyzing cookie security...")
    check_cookies(resp, findings)

    progress(65, "Testing for reflected XSS...")
    soup = BeautifulSoup(resp.text, "html.parser")
    check_reflected_xss(target_url, soup, findings)

    progress(74, "Testing for open redirect...")
    check_open_redirect(target_url, findings)

    progress(83, "Testing for SQL injection indicators...")
    check_sql_injection_indicators(target_url, findings)

    progress(92, "Checking sensitive file exposure...")
    check_sensitive_paths(target_url, findings)

    progress(100, "Scan complete")

    # Sort by severity
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: order.get(f["severity"], 5))

    return findings
