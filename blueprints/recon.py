from flask import Blueprint, render_template, request, flash
from services.recon import run_network_recon

bp = Blueprint('recon', __name__)

@bp.route('/recon', methods=['GET', 'POST'])
def network_recon():
    result = None
    error = None
    domain = ''
    
    if request.method == 'POST':
        domain = request.form.get('domain', '').strip()
        if not domain:
            flash('Please enter a domain name.', 'error')
        else:
            result, error = run_network_recon(domain)
            if error:
                flash(error, 'error')
    
    return render_template('recon.html', result=result, domain=domain)