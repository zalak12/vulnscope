from flask import Blueprint, jsonify
from models import Scan

bp = Blueprint('api', __name__)


@bp.route('/health')
def health():
    return jsonify({'status': 'ok', 'scans': Scan.query.count()})