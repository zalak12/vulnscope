import uuid
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from models import db, Scan
from services.scanner import run_scan, validate_url

bp = Blueprint('scans', __name__)


@bp.route('/scan/new', methods=['GET'])
def new_scan():
    return render_template('new_scan.html')


@bp.route('/scan/start', methods=['POST'])
def start_scan():
    target = (request.form.get('target_url') or '').strip()
    profile = request.form.get('profile', 'passive')
    name = (request.form.get('name') or '').strip() or None
    authorized = request.form.get('authorized') == 'on'

    if not authorized:
        flash('You must confirm authorization before scanning.', 'error')
        return redirect(url_for('scans.new_scan'))

    ok, err = validate_url(target)
    if not ok:
        flash(err, 'error')
        return redirect(url_for('scans.new_scan'))

    scan = Scan(
        scan_id='S-' + uuid.uuid4().hex[:10].upper(),
        name=name,
        target_url=target,
        profile=profile,
        status='running',
    )
    db.session.add(scan)
    db.session.commit()

    run_scan(scan.scan_id)
    return redirect(url_for('scans.results', scan_id=scan.scan_id))


@bp.route('/scan/<scan_id>')
def results(scan_id):
    scan = Scan.query.filter_by(scan_id=scan_id).first_or_404()
    return render_template('scan_results.html', scan=scan)


@bp.route('/scan/<scan_id>/status')
def status(scan_id):
    scan = Scan.query.filter_by(scan_id=scan_id).first_or_404()
    return jsonify({
        'status': scan.status,
        'finding_count': scan.finding_count,
        'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
    })


@bp.route('/history')
def history():
    q = (request.args.get('q') or '').strip()
    query = Scan.query
    if q:
        query = query.filter(Scan.target_url.ilike(f'%{q}%'))
    scans = query.order_by(Scan.started_at.desc()).all()
    return render_template('history.html', scans=scans, q=q)

    import uuid
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from models import db, Scan
from services.scanner import run_scan, validate_url

bp = Blueprint('scans', __name__)


@bp.route('/scan/new', methods=['GET'])
def new_scan():
    return render_template('new_scan.html')


@bp.route('/scan/start', methods=['POST'])
def start_scan():
    target = (request.form.get('target_url') or '').strip()
    profile = request.form.get('profile', 'passive')
    name = (request.form.get('name') or '').strip() or None
    authorized = request.form.get('authorized') == 'on'

    if not authorized:
        flash('You must confirm authorization before scanning.', 'error')
        return redirect(url_for('scans.new_scan'))

    ok, err = validate_url(target)
    if not ok:
        flash(err, 'error')
        return redirect(url_for('scans.new_scan'))

    scan = Scan(
        scan_id='S-' + uuid.uuid4().hex[:10].upper(),
        name=name,
        target_url=target,
        profile=profile,
        status='running',
    )
    db.session.add(scan)
    db.session.commit()

    run_scan(scan.scan_id)
    return redirect(url_for('scans.results', scan_id=scan.scan_id))


@bp.route('/scan/<scan_id>')
def results(scan_id):
    scan = Scan.query.filter_by(scan_id=scan_id).first_or_404()
    return render_template('scan_results.html', scan=scan)


# NAYA ROUTE: Scan Delete karne ke liye
@bp.route('/scan/<scan_id>/delete', methods=['POST'])
def delete_scan(scan_id):
    scan = Scan.query.filter_by(scan_id=scan_id).first_or_404()
    db.session.delete(scan)
    db.session.commit()
    flash('Scan deleted successfully.', 'success')
    return redirect(url_for('scans.history'))


@bp.route('/scan/<scan_id>/status')
def status(scan_id):
    scan = Scan.query.filter_by(scan_id=scan_id).first_or_404()
    return jsonify({
        'status': scan.status,
        'finding_count': scan.finding_count,
        'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
    })


@bp.route('/history')
def history():
    q = (request.args.get('q') or '').strip()
    query = Scan.query
    if q:
        query = query.filter(Scan.target_url.ilike(f'%{q}%'))
    scans = query.order_by(Scan.started_at.desc()).all()
    return render_template('history.html', scans=scans, q=q)