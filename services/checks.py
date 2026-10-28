import socket
import ssl
import datetime
import re
from urllib.parse import urlparse
from .scoring import SEVERITY_ORDER

SECURITY_HEADERS = {
    'Content-Security-Policy': {
        'severity': 'medium',
        'explanation': 'CSP helps mitigate XSS and injection by restricting sources of executable content.',
        'remediation': 'Add the following to your server configuration:\n\n# Nginx\nadd_header Content-Security-Policy "default-src \'self\';" always;\n\n# Apache\nHeader set Content-Security-Policy "default-src \'self\';"'
    },
    'Strict-Transport-Security': {
        'severity': 'medium',
        'explanation': 'HSTS enforces HTTPS for future visits, preventing downgrade attacks.',
        'remediation': 'Add the following to your server configuration:\n\n# Nginx\nadd_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;\n\n# Apache\nHeader set Strict-Transport-Security "max-age=31536000; includeSubDomains"'
    },
    'X-Content-Type-Options': {
        'severity': 'low',
        'explanation': 'Prevents MIME-type sniffing that can turn benign files into executable scripts.',
        'remediation': 'Add the following to your server configuration:\n\n# Nginx\nadd_header X-Content-Type-Options "nosniff" always;\n\n# Apache\nHeader set X-Content-Type-Options "nosniff"'
    },
    'X-Frame-Options': {
        'severity': 'low',
        'explanation': 'Mitigates clickjacking by blocking the page from being framed.',
        'remediation': 'Add the following to your server configuration:\n\n# Nginx\nadd_header X-Frame-Options "DENY" always;\n\n# Apache\nHeader set X-Frame-Options "DENY"'
    },
    'Referrer-Policy': {
        'severity': 'low',
        'explanation': 'Controls how much referrer information is leaked to other origins.',
        'remediation': 'Add the following to your server configuration:\n\n# Nginx\nadd_header Referrer-Policy "strict-origin-when-cross-origin" always;\n\n# Apache\nHeader set Referrer-Policy "strict-origin-when-cross-origin"'
    },
    'Permissions-Policy': {
        'severity': 'informational',
        'explanation': 'Restricts access to powerful browser features (camera, geolocation, etc.).',
        'remediation': 'Add the following to your server configuration:\n\n# Nginx\nadd_header Permissions-Policy "geolocation=(), camera=()" always;\n\n# Apache\nHeader set Permissions-Policy "geolocation=(), camera=()"'
    },
}

def check_https_and_tls(url, hostname, timeout):
    findings = []
    parsed = urlparse(url)
    if parsed.scheme != 'https':
        findings.append({
            'check_name': 'HTTPS/TLS',
            'title': 'Website is served over plain HTTP',
            'severity': 'high',
            'confidence': 'high',
            'affected_url': url,
            'evidence': f'Scheme observed: {parsed.scheme}',
            'explanation': 'Traffic sent over HTTP is unencrypted and can be intercepted or modified by an attacker.',
            'remediation': '1. Install a valid SSL/TLS certificate (e.g., Let\'s Encrypt).\n2. Configure your web server to listen on port 443.\n3. Add a redirect rule from HTTP to HTTPS:\n\n# Nginx\nserver {\n    listen 80;\n    return 301 https://$host$request_uri;\n}',
        })
        return findings

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        if cert:
            not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_left = (not_after - datetime.datetime.utcnow()).days
            if days_left < 0:
                findings.append({
                    'check_name': 'HTTPS/TLS',
                    'title': 'TLS certificate has expired',
                    'severity': 'high',
                    'confidence': 'high',
                    'affected_url': url,
                    'evidence': f'Certificate expired on {not_after.isoformat()}',
                    'explanation': 'Expired certificates cause browser warnings and undermine trust.',
                    'remediation': 'Renew your SSL/TLS certificate immediately. If using Let\'s Encrypt, run:\nsudo certbot renew',
                })
            elif days_left < 30:
                findings.append({
                    'check_name': 'HTTPS/TLS',
                    'title': f'TLS certificate expires soon ({days_left} days)',
                    'severity': 'low',
                    'confidence': 'high',
                    'affected_url': url,
                    'evidence': f'Certificate expires on {not_after.isoformat()}',
                    'explanation': 'Certificates should be renewed before expiration to avoid outages.',
                    'remediation': 'Set up automated certificate renewal. For Let\'s Encrypt:\nsudo certbot renew --dry-run',
                })
    except ssl.SSLCertVerificationError as e:
        findings.append({
            'check_name': 'HTTPS/TLS',
            'title': 'TLS certificate failed verification',
            'severity': 'high',
            'confidence': 'high',
            'affected_url': url,
            'evidence': str(e)[:300],
            'explanation': 'An untrusted certificate allows interception by an attacker holding a different certificate.',
            'remediation': 'Install a valid certificate from a trusted Certificate Authority (CA) like Let\'s Encrypt.',
        })
    except Exception as e:
        findings.append({
            'check_name': 'HTTPS/TLS',
            'title': 'Unable to fully inspect TLS certificate',
            'severity': 'informational',
            'confidence': 'low',
            'affected_url': url,
            'evidence': f'{type(e).__name__}: {str(e)[:200]}',
            'explanation': 'TLS inspection could not complete; this is not a vulnerability by itself.',
            'remediation': 'Manually verify TLS configuration with a dedicated TLS scanner.',
        })
    return findings

def check_security_headers(resp, url):
    findings = []
    for header, meta in SECURITY_HEADERS.items():
        if header not in resp.headers:
            findings.append({
                'check_name': 'Security Headers',
                'title': f'Missing security header: {header}',
                'severity': meta['severity'],
                'confidence': 'high',
                'affected_url': url,
                'evidence': f'Header "{header}" absent from response.',
                'explanation': meta['explanation'],
                'remediation': meta['remediation'],
            })
    return findings

def check_cookies(resp, url):
    findings = []
    cookies = resp.headers.getlist('Set-Cookie') if hasattr(resp.headers, 'getlist') else []
    for raw in cookies:
        name = raw.split('=', 1)[0].strip()
        missing = []
        if 'secure' not in raw.lower():
            missing.append('Secure')
        if 'httponly' not in raw.lower():
            missing.append('HttpOnly')
        if 'samesite' not in raw.lower():
            missing.append('SameSite')
        if missing:
            fix_code = f"# Example (Node.js/Express)\nres.cookie('{name}', 'value', {{\n"
            if 'Secure' in missing: fix_code += "  secure: true,\n"
            if 'HttpOnly' in missing: fix_code += "  httpOnly: true,\n"
            if 'SameSite' in missing: fix_code += "  sameSite: 'strict'\n"
            fix_code += "});"
            
            findings.append({
                'check_name': 'Cookie Security',
                'title': f'Cookie "{name}" missing attributes: {", ".join(missing)}',
                'severity': 'low',
                'confidence': 'medium',
                'affected_url': url,
                'evidence': f'Cookie: {name}; missing: {", ".join(missing)}',
                'explanation': 'Missing cookie flags weaken protection against XSS (HttpOnly), CSRF/SameSite, and network interception (Secure).',
                'remediation': f'Update your application code to set the missing flags when creating the cookie.\n\n{fix_code}',
            })
    return findings

def check_info_disclosure(resp, url):
    findings = []
    for h in ('Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Generator'):
        if h in resp.headers:
            findings.append({
                'check_name': 'Information Disclosure',
                'title': f'Technology disclosure via "{h}" header',
                'severity': 'informational',
                'confidence': 'high',
                'affected_url': url,
                'evidence': f'{h}: {resp.headers[h][:100]}',
                'explanation': 'Version banners help attackers fingerprint the stack and target known CVEs.',
                'remediation': f'Hide the {h} header.\n\n# Nginx\nserver_tokens off;\nproxy_hide_header {h};\n\n# Apache\nServerTokens Prod\nServerSignature Off',
            })
    return findings

PUBLIC_PATHS = ['/robots.txt', '/sitemap.xml', '/.well-known/security.txt']

def check_public_resources(session, base, timeout):
    findings = []
    for path in PUBLIC_PATHS:
        target = base.rstrip('/') + path
        try:
            r = session.get(target, timeout=timeout, allow_redirects=False)
        except Exception:
            continue
        if r.status_code == 200 and path == '/.well-known/security.txt':
            findings.append({
                'check_name': 'Public Resources',
                'title': 'security.txt present (positive indicator)',
                'severity': 'informational',
                'confidence': 'high',
                'affected_url': target,
                'evidence': f'HTTP 200 returned for {path}',
                'explanation': 'A security.txt file helps researchers report vulnerabilities responsibly.',
                'remediation': 'None required — maintain current file.',
            })
    return findings

def check_dns(hostname):
    findings = []
    try:
        infos = socket.getaddrinfo(hostname, None)
        ips = sorted({i[4][0] for i in infos})
        if ips:
            findings.append({
                'check_name': 'DNS',
                'title': f'Domain resolves to {len(ips)} address(es)',
                'severity': 'informational',
                'confidence': 'high',
                'affected_url': hostname,
                'evidence': 'Resolved IPs: ' + ', '.join(ips[:5]),
                'explanation': 'DNS resolution information gathered for context only.',
                'remediation': 'No action required.',
            })
    except socket.gaierror as e:
        findings.append({
            'check_name': 'DNS',
            'title': 'DNS resolution failed',
            'severity': 'informational',
            'confidence': 'medium',
            'affected_url': hostname,
            'evidence': str(e)[:200],
            'explanation': 'The hostname could not be resolved from this scanner environment.',
            'remediation': 'Verify DNS configuration manually.',
        })
    return findings

# --- ACTIVE CHECKS (SQLi, XSS, DIR BRUTE) ---

def check_reflected_xss(session, url, timeout):
    findings = []
    payload = "<script>alert('VulnScope_XSS')</script>"
    test_url = f"{url}?q={payload}"
    try:
        r = session.get(test_url, timeout=timeout)
        if payload in r.text:
            findings.append({
                'check_name': 'Active - XSS',
                'title': 'Potential Reflected XSS Detected',
                'severity': 'high',
                'confidence': 'medium',
                'affected_url': test_url,
                'evidence': f'Payload reflected in response: {payload}',
                'explanation': 'The application reflects unsanitized user input back in the HTML response, allowing attackers to execute malicious JavaScript in a victim\'s browser.',
                'remediation': '1. Validate and sanitize all user inputs.\n2. Use HTML entity encoding for output.\n3. Implement a strict Content-Security-Policy (CSP).'
            })
    except Exception:
        pass
    return findings

def check_sql_injection(session, url, timeout):
    findings = []
    payload = "'"
    test_url = f"{url}?id={payload}"
    try:
        r = session.get(test_url, timeout=timeout)
        sql_errors = [
            "you have an error in your sql syntax",
            "unclosed quotation mark after the character string",
            "microsoft ole db provider for sql server",
            "mysql_fetch_array()",
            "pg_query()"
        ]
        lower_text = r.text.lower()
        for error in sql_errors:
            if error in lower_text:
                findings.append({
                    'check_name': 'Active - SQLi',
                    'title': 'Potential SQL Injection Detected',
                    'severity': 'critical',
                    'confidence': 'medium',
                    'affected_url': test_url,
                    'evidence': f'Database error string found in response: "{error}"',
                    'explanation': 'The application returns raw database error messages when malformed SQL syntax is supplied, indicating unsanitized input reaches the database.',
                    'remediation': '1. Use Prepared Statements / Parameterized Queries.\n2. Hide raw database errors from the frontend.'
                })
                break
    except Exception:
        pass
    return findings

def check_directory_exposure(session, base_url, timeout):
    findings = []
    paths = ['/admin', '/backup.zip', '/.env', '/config.php']
    for path in paths:
        target = base_url.rstrip('/') + path
        try:
            r = session.get(target, timeout=timeout, allow_redirects=False)
            if r.status_code == 200:
                findings.append({
                    'check_name': 'Active - Dir Exposure',
                    'title': f'Exposed Directory/File: {path}',
                    'severity': 'high',
                    'confidence': 'high',
                    'affected_url': target,
                    'evidence': f'HTTP 200 OK returned for {path}',
                    'explanation': 'Sensitive files or admin panels are publicly accessible without authentication.',
                    'remediation': f'Restrict access to {path} via server configuration, firewall, or authentication.'
                })
        except Exception:
            pass
    return findings