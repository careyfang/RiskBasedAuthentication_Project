from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class TrustedLocation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    country = db.Column(db.String(100))
    region = db.Column(db.String(100))
    city = db.Column(db.String(100))
    user = db.relationship('User', backref=db.backref('trusted_locations', lazy=True))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    security_question = db.Column(db.String(200), nullable=False)
    security_answer = db.Column(db.String(200), nullable=False)
    failed_attempts = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=False)  # For email confirmation
    is_locked = db.Column(db.Boolean, default=False)  # New field for account locking


class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    ip_address = db.Column(db.String(100), nullable=False)
    user_agent = db.Column(db.String(300), nullable=False)
    login_time = db.Column(db.DateTime, nullable=False)
    label = db.Column(db.Integer, nullable=False)  # Label for ML (0: legitimate, 1: anomalous)
    country = db.Column(db.String(100))
    region = db.Column(db.String(100))
    city = db.Column(db.String(100))
    login_day = db.Column(db.Integer)  # 0 = Monday, 6 = Sunday
    login_hour = db.Column(db.Integer)
