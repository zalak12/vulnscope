from flask import Flask, render_template
from config import Config
from models import db
from blueprints.dashboard import bp as dashboard_bp
from blueprints.scans import bp as scans_bp
from blueprints.findings import bp as findings_bp
from blueprints.reports import bp as reports_bp
from blueprints.api import bp as api_bp
from blueprints.recon import bp as recon_bp

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(scans_bp)
    app.register_blueprint(findings_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(recon_bp)

    # Landing Page Route (Root URL)
    @app.route('/')
    def landing():
        return render_template('landing.html')

    # Settings Route
    @app.route('/settings')
    def settings():
        return render_template('settings.html')

    @app.errorhandler(404)
    def not_found(e):
        return render_template('error.html', code='404', message='Page Not Found'), 404

    @app.errorhandler(500)
    def internal_error(e):
        return render_template('error.html', code='500', message='Internal Server Error'), 500

    with app.app_context():
        db.create_all()

    return app


app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)