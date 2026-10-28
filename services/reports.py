import json
from datetime import datetime


def scan_to_dict(scan):
    return {
        'scan_id': scan.scan_id,
        'name': scan.name,
        'target_url': scan.target_url,
        'final_url': scan.final_url,
        'profile': scan.profile,
        'status': scan.status,
        'http_status': scan.http_status,
        'response_time_ms': scan.response_time_ms,
        'started_at': scan.started_at.isoformat() if scan.started_at else None,
        'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
        'findings': [{
            'finding_id': f.finding_id,
            'check_name': f.check_name,
            'title': f.title,
            'severity': f.severity,
            'confidence': f.confidence,
            'affected_url': f.affected_url,
            'evidence': f.evidence,
            'explanation': f.explanation,
            'remediation': f.remediation,
            'detection_time': f.detection_time.isoformat() if f.detection_time else None,
        } for f in scan.findings],
    }


def build_json(scan):
    return json.dumps(scan_to_dict(scan), indent=2)