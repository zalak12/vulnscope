from flask import Blueprint, render_template
from models import Scan, Finding, db
from sqlalchemy import func
from datetime import datetime, timedelta

bp = Blueprint('dashboard', __name__)


@bp.route('/dashboard')
def overview():
    total_scans = Scan.query.count()
    completed = Scan.query.filter_by(status='completed').count()
    sites_with_findings = db.session.query(func.count(func.distinct(Scan.target_url))).join(
        Finding, Finding.scan_id == Scan.id
    ).scalar() or 0
    high_sev = Finding.query.filter(Finding.severity.in_(['high', 'critical'])).count()

    recent = Scan.query.order_by(Scan.started_at.desc()).limit(8).all()

    severity_counts = dict(db.session.query(Finding.severity, func.count(Finding.id))
                           .group_by(Finding.severity).all())

    # Last 7 days scan trend logic
    today = datetime.utcnow().date()
    last_7_days = [(today - timedelta(days=i)).strftime('%Y-%m-%d') for i in range(6, -1, -1)]
    
    scans_per_day = {day: 0 for day in last_7_days}
    all_scans = Scan.query.filter(Scan.started_at >= datetime.utcnow() - timedelta(days=7)).all()
    
    for s in all_scans:
        if s.started_at:
            day_str = s.started_at.strftime('%Y-%m-%d')
            if day_str in scans_per_day:
                scans_per_day[day_str] += 1

    trend_labels = list(scans_per_day.keys())
    trend_data = list(scans_per_day.values())

    return render_template(
        'dashboard.html',
        total_scans=total_scans,
        completed=completed,
        sites_with_findings=sites_with_findings,
        high_sev=high_sev,
        recent=recent,
        severity_counts=severity_counts,
        trend_labels=trend_labels,
        trend_data=trend_data,
    )