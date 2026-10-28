SEVERITY_ORDER = {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'informational': 1}

def severity_color(sev):
    return {
        'critical': '#ef4444',
        'high': '#f97316',
        'medium': '#f59e0b',
        'low': '#3b82f6',
        'informational': '#64748b',
    }.get((sev or '').lower(), '#64748b')

def summarize(findings):
    counts = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    return counts

def calculate_risk_score(findings):
    score = 100
    for f in findings:
        if f.severity == 'critical': score -= 25
        elif f.severity == 'high': score -= 15
        elif f.severity == 'medium': score -= 8
        elif f.severity == 'low': score -= 3
        elif f.severity == 'informational': score -= 1
    
    if score < 0:
        score = 0
    return score

def get_ai_explanation(finding_title, severity):
    title = finding_title.lower()
    if 'csp' in title or 'content-security-policy' in title:
        return f"This issue is rated {severity} because missing CSP allows attackers to inject malicious scripts (XSS) into your pages."
    elif 'hsts' in title or 'strict-transport-security' in title:
        return f"This is {severity} risk. Without HSTS, users can be tricked into using insecure HTTP connections, exposing sensitive data."
    elif 'xss' in title:
        return f"Critical {severity} issue. Attackers can steal user cookies or perform actions on behalf of users."
    elif 'sql' in title:
        return f"Highly {severity} issue. Attackers might be able to read or modify your entire database."
    elif 'server' in title or 'powered-by' in title:
        return f"This is {severity} risk. It helps attackers know exactly which software version you are running so they can find known exploits for it."
    else:
        return f"This is a {severity} priority issue that should be addressed to strengthen your overall security posture."