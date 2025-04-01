from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    # Define relationships
    scan_results = db.relationship('ScanResult', backref='user', lazy='dynamic')
    security_events = db.relationship('SecurityEvent', backref='user', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    url = db.Column(db.String(255), nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Enhanced scan results
    security_score = db.Column(db.Integer)  # 0-100
    risk_level = db.Column(db.String(20))  # high, medium, low
    scan_duration = db.Column(db.Float)  # in seconds
    server_info = db.Column(db.JSON)
    technologies = db.Column(db.JSON)
    headers = db.Column(db.JSON)
    vulnerabilities = db.Column(db.JSON)
    recommendations = db.Column(db.JSON)

    def __repr__(self):
        return f'<ScanResult {self.url}>'

class SecurityEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_type = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(200))

    def __repr__(self):
        return f'<SecurityEvent {self.event_type}>' 