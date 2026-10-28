from flask import Blueprint, render_template, request
from models import Finding, Scan

bp = Blueprint('findings', __name__)


@bp.route('/findings')
def list_findings():
    sev = request.args.get('severity')
    q = Finding.query
    if sev:
        q = q.filter(Finding.severity == sev)
    findings = q.order_by(Finding.detection_time.desc()).limit(200).all()
    return render_template('findings.html', findings=findings, sev=sev)


@bp.route('/finding/<finding_id>')
def detail(finding_id):
    f = Finding.query.filter_by(finding_id=finding_id).first_or_404()
    return render_template('finding_detail.html', finding=f)