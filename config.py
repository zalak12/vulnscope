import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'vulnscope-dev-key-change-in-prod')
    SQLALCHEMY_DATABASE_URI = 'sqlite:///vulnscope.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SCAN_TIMEOUT = 10
    MAX_REDIRECTS = 5
    USER_AGENT = 'VulnScope/1.0 (Security Assessment; Authorized Scans Only)'
    MAX_RESPONSE_BYTES = 500 * 1024