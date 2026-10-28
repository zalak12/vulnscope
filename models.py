from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Scan(db.Model):
    __tablename__ = 'scans'
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.String(32), unique=True, nullable=False, index=True)
    name = db.Column(db.String(200))
    target_url = db.Column(db.String(500), nullable=False)
    final_url = db.Column(db.String(500))
    profile = db.Column(db.String(50), default='standard')
    status = db.Column(db.String(30), default='pending')
    http_status = db.Column(db.Integer)
    response_time_ms = db.Column(db.Integer)
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    error_message = db.Column(db.Text)
    risk_score = db.Column(db.Integer, default=100) # <-- NAYA COLUMN
    
    findings = db.relationship('Finding', backref='scan', lazy=True, cascade='all, delete-orphan')

    @property
    def highest_severity(self):
        order = {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'informational': 1}
        severities = [f.severity for f in self.findings if f.severity]
        if not severities:
            return None
        return max(severities, key=lambda s: order.get(s, 0))

    @property
    def finding_count(self):
        return len(self.findings)


class Finding(db.Model):
    __tablename__ = 'findings'
    id = db.Column(db.Integer, primary_key=True)
    finding_id = db.Column(db.String(40), unique=True, nullable=False)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    check_name = db.Column(db.String(80))
    title = db.Column(db.String(300))
    severity = db.Column(db.String(20))
    confidence = db.Column(db.String(20))
    affected_url = db.Column(db.String(500))
    evidence = db.Column(db.Text)
    explanation = db.Column(db.Text)
    remediation = db.Column(db.Text)
    detection_time = db.Column(db.DateTime, default=datetime.utcnow)

    SEVERITY_ORDER = {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'informational': 1}