import uuid
import re
import time
from datetime import datetime
from urllib.parse import urlparse
import requests

from config import Config
from models import db, Scan, Finding
from .checks import (
    check_https_and_tls, check_security_headers, check_cookies,
    check_info_disclosure, check_public_resources, check_dns,
    check_reflected_xss, check_sql_injection, check_directory_exposure
)
from .scoring import calculate_risk_score, get_ai_explanation

URL_RE = re.compile(r'^https?://[a-zA-Z0-9\.\-]+(:[0-9]+)?(/.*)?$')

def validate_url(url):
    if not url or not URL_RE.match(url.strip()):
        return False, 'Please enter a valid http(s) URL.'
    return True, None

def _new_finding_id():
    return 'F-' + uuid.uuid4().hex[:12].upper()

def _persist(scan, findings):
    for f in findings:
        # AI Analyst update
        f['explanation'] = f.get('explanation', '') + "\n\n🧠 AI Analyst: " + get_ai_explanation(f.get('title', ''), f.get('severity', ''))
        
        # Basic CVE Intelligence
        if f.get('check_name') == 'Information Disclosure' and 'Server' in f.get('title', ''):
            f['remediation'] += "\n\n🗂️ CVE Intelligence: Try searching for known vulnerabilities for this server version on cve.mitre.org or nvd.nist.gov."
            
        db.session.add(Finding(
            finding_id=_new_finding_id(),
            scan_id=scan.id,
            check_name=f.get('check_name'),
            title=f.get('title'),
            severity=f.get('severity'),
            confidence=f.get('confidence'),
            affected_url=f.get('affected_url'),
            evidence=f.get('evidence'),
            explanation=f.get('explanation'),
            remediation=f.get('remediation'),
        ))

def run_scan(scan_id):
    scan = Scan.query.filter_by(scan_id=scan_id).first()
    if not scan:
        return
    scan.status = 'running'
    db.session.commit()

    findings = []
    try:
        ok, err = validate_url(scan.target_url)
        if not ok:
            scan.status = 'failed'
            scan.error_message = err
            scan.completed_at = datetime.utcnow()
            db.session.commit()
            return

        parsed = urlparse(scan.target_url)
        hostname = parsed.hostname or ''
        session = requests.Session()
        session.headers.update({'User-Agent': Config.USER_AGENT})

        t0 = time.time()
        resp = session.get(scan.target_url, timeout=Config.SCAN_TIMEOUT, allow_redirects=True)
        elapsed_ms = int((time.time() - t0) * 1000)

        scan.final_url = resp.url
        scan.http_status = resp.status_code
        scan.response_time_ms = elapsed_ms

        if resp.history:
            chain = ' -> '.join([r.url for r in resp.history] + [resp.url])
            findings.append({
                'check_name': 'HTTP/Redirects',
                'title': f'Redirect chain of length {len(resp.history)}',
                'severity': 'informational',
                'confidence': 'high',
                'affected_url': scan.target_url,
                'evidence': chain[:400],
                'explanation': 'Redirects were followed to reach the final destination.',
                'remediation': 'No action required unless redirects lead to unintended hosts.',
            })

        findings.extend(check_https_and_tls(resp.url, hostname, Config.SCAN_TIMEOUT))
        findings.extend(check_security_headers(resp, resp.url))
        findings.extend(check_cookies(resp, resp.url))
        findings.extend(check_info_disclosure(resp, resp.url))
        findings.extend(check_dns(hostname))

        if scan.profile in ['standard', 'active']:
            findings.extend(check_public_resources(session, resp.url, Config.SCAN_TIMEOUT))

        if scan.profile == 'active':
            findings.extend(check_reflected_xss(session, resp.url, Config.SCAN_TIMEOUT))
            findings.extend(check_sql_injection(session, resp.url, Config.SCAN_TIMEOUT))
            findings.extend(check_directory_exposure(session, resp.url, Config.SCAN_TIMEOUT))

        _persist(scan, findings)
        
        # Calculate Risk Score before saving
        scan.risk_score = calculate_risk_score(scan.findings)
        
        scan.status = 'completed'
        scan.completed_at = datetime.utcnow()
        db.session.commit()

    except requests.exceptions.Timeout:
        scan.status = 'failed'
        scan.error_message = 'Request timed out.'
        scan.completed_at = datetime.utcnow()
        db.session.commit()
    except requests.exceptions.ConnectionError as e:
        scan.status = 'failed'
        scan.error_message = 'Connection failed: ' + str(e)[:200]
        scan.completed_at = datetime.utcnow()
        db.session.commit()
    except Exception as e:
        scan.status = 'failed'
        scan.error_message = f'{type(e).__name__}: {str(e)[:200]}'
        scan.completed_at = datetime.utcnow()
        db.session.commit()