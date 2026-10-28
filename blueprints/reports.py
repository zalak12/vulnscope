from flask import Blueprint, render_template, Response
from models import Scan
from services.reports import build_json, scan_to_dict
from services.recon import run_network_recon
import json

bp = Blueprint('reports', __name__)

@bp.route('/reports')
def index():
    scans = Scan.query.filter_by(status='completed').order_by(Scan.started_at.desc()).all()
    return render_template('reports.html', scans=scans)

@bp.route('/reports/<scan_id>.json')
def download_json(scan_id):
    scan = Scan.query.filter_by(scan_id=scan_id).first_or_404()
    payload = build_json(scan)
    return Response(payload, mimetype='application/json',
                    headers={'Content-Disposition': f'attachment; filename=vulnscope-{scan_id}.json'})

@bp.route('/reports/<scan_id>.html')
def download_html(scan_id):
    scan = Scan.query.filter_by(scan_id=scan_id).first_or_404()
    data = scan_to_dict(scan)
    
    # NAYA: Network Recon data bhi fetch kar rahe hain report ke liye
    recon_data = None
    if scan.target_url:
        recon_data, _ = run_network_recon(scan.target_url)
        
    return render_template('report.html', data=data, recon=recon_data)