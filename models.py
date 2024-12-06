from flask_sqlalchemy import SQLAlchemy
import datetime

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
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(200), nullable=True)
    login_time = db.Column(db.DateTime, nullable=False)
    login_hour = db.Column(db.Integer, nullable=False)
    login_day = db.Column(db.Integer, nullable=False)
    country = db.Column(db.String(100), nullable=True)
    region = db.Column(db.String(100), nullable=True)
    city = db.Column(db.String(100), nullable=True)
    label = db.Column(db.Integer, nullable=False)
    is_trusted_country = db.Column(db.Boolean, default=False, nullable=False)
    is_trusted_region = db.Column(db.Boolean, default=False, nullable=False)
    is_trusted_city = db.Column(db.Boolean, default=False, nullable=False)


class TrustedDevice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user_agent = db.Column(db.String(500), nullable=False)
    added_time = db.Column(db.DateTime, default=datetime.datetime.now)
    user = db.relationship('User', backref=db.backref('trusted_devices', lazy=True))
