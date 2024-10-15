from flask import Blueprint
from .google_login import google_login_bp
from .targets import targets_bp
from .vulnerabilities import vulnerabilities_bp
from .jobs import jobs_bp
from .customnuclei import customnuclei_bp

api_bp = Blueprint('api', __name__)

# Register for API paths
api_bp.register_blueprint(google_login_bp, url_prefix='/google-login')
api_bp.register_blueprint(targets_bp, url_prefix='/targets')
api_bp.register_blueprint(vulnerabilities_bp, url_prefix='/vulnerabilities')
api_bp.register_blueprint(jobs_bp, url_prefix='/jobs')
api_bp.register_blueprint(customnuclei_bp, url_prefix='/customnuclei')