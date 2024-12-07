from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify
from models import db, User, LoginAttempt, TrustedLocation, TrustedDevice
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
from random import randint
import requests
import pandas as pd
import numpy as np
import os
from sklearn.preprocessing import LabelEncoder, StandardScaler
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from dotenv import load_dotenv
from sklearn.ensemble import GradientBoostingClassifier
import logging
from imblearn.over_sampling import SMOTE
import random
from apscheduler.schedulers.background import BackgroundScheduler
import joblib
from geopy.distance import geodesic
from geopy.geocoders import Nominatim
from geopy.exc import GeocoderTimedOut, GeocoderUnavailable
import time

from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.metrics import accuracy_score, classification_report
from sklearn.pipeline import Pipeline
from scipy.stats import uniform, randint
from flask_migrate import Migrate

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure, random key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rba.db'

# Load environment variables for email credentials
load_dotenv()
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)

# Initialize global variables
model = None
model_features = []
encoders = {}
MODEL = None  # Will hold the entire ML pipeline

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, 'models')
MODEL_PATH = os.path.join(MODEL_DIR, 'model.joblib')
ENCODERS_PATH = os.path.join(MODEL_DIR, 'encoders.joblib')
MODEL_FEATURES_PATH = os.path.join(MODEL_DIR, 'model_features.joblib')

geolocator = Nominatim(user_agent="rba_application")
LOCATION_CACHE = {}

def safe_encode(feature, value):
    """Safely encode a feature using the corresponding encoder."""
    try:
        return encoders[feature].transform([value])[0]
    except:
        try:
            return encoders[feature].transform(['Unknown'])[0]
        except:
            return 0

def categorize_user_agent(user_agent):
    """Categorize user agent into broad categories: mobile, desktop, unknown."""
    ua = user_agent.lower()
    if 'mobile' in ua or 'android' in ua or 'iphone' in ua:
        return 'mobile'
    elif 'windows' in ua or 'mac os' in ua:
        return 'desktop'
    else:
        return 'unknown'

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/unlock_account', methods=['GET', 'POST'])
def unlock_account():
    if request.method == 'POST':
        if 'username' in request.form:
            username = request.form['username']
            user = User.query.filter_by(username=username).first()
            if user:
                session['unlock_username'] = username
                return render_template('security_question.html', question=user.security_question)
            else:
                flash('Username not found. Please try again.')
                return render_template('unlock_account.html')
        elif 'security_answer' in request.form:
            security_answer = request.form['security_answer']
            username = session.get('unlock_username')
            if not username:
                flash('Session expired. Please try unlocking your account again.')
                return redirect(url_for('unlock_account'))
            user = User.query.filter_by(username=username).first()
            if user and check_password_hash(user.security_answer, security_answer):
                user.failed_attempts = 0
                user.is_locked = False
                db.session.commit()
                flash('Your account has been unlocked. You can now log in.')
                session.pop('unlock_username', None)
                return redirect(url_for('login'))
            else:
                flash('Incorrect security answer. Please try again.')
                return render_template('security_question.html', question=user.security_question)
    return render_template('unlock_account.html')

@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=3600)
    except Exception as e:
        logger.error(f"Email confirmation error: {e}")
        return 'The confirmation link is invalid or has expired.', 400

    user = User.query.filter_by(email=email).first()
    if user:
        user.is_active = True
        db.session.commit()
        return render_template('email_confirmed.html')
    else:
        return 'User not found.', 404

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        email = request.form['email']
        security_question = request.form['security_question']
        security_answer = generate_password_hash(request.form['security_answer'])

        if password != confirm_password:
            flash('Passwords do not match. Please try again.')
            return render_template('register.html')

        existing_user = User.query.filter_by(username=username).first()
        existing_email = User.query.filter_by(email=email).first()
        
        if existing_user:
            flash('Username already exists. Please choose another one.')
            return render_template('register.html')
        
        if existing_email:
            flash('Email already registered. Please use a different email.')
            return render_template('register.html')

        try:
            password_hash = generate_password_hash(password)
            new_user = User(
                username=username,
                password=password_hash,
                email=email,
                security_question=security_question,
                security_answer=security_answer
            )
            db.session.add(new_user)
            db.session.commit()
            
            try:
                token = serializer.dumps(email, salt='email-confirm')
                confirm_url = url_for('confirm_email', token=token, _external=True)
                msg = Message('Confirm Your Email', sender=app.config['MAIL_USERNAME'], recipients=[email])
                msg.body = f'Please click the link to confirm your email: {confirm_url}'
                mail.send(msg)
                logger.info(f"Verification email sent to {email}")
            except Exception as e:
                logger.error(f"Failed to send verification email: {e}")
                flash('Registration successful but failed to send verification email. Contact support.')
                return redirect(url_for('login'))
            
            flash('Registration successful! Please check your email to confirm your account.')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Registration error: {e}")
            flash('An error occurred during registration. Please try again.')
            return render_template('register.html')

    return render_template('register.html')

@app.route('/security_question', methods=['GET', 'POST'])
def security_question():
    if request.method == 'POST':
        user_id = session.get('user_id')
        if not user_id:
            return redirect(url_for('login'))

        user = db.session.get(User, user_id)
        if not user:
            return redirect(url_for('login'))

        entered_answer = request.form.get('security_answer', '').strip().lower()
        if entered_answer and check_password_hash(user.security_answer, entered_answer):
            login_attempt = LoginAttempt.query.filter_by(user_id=user_id).order_by(LoginAttempt.id.desc()).first()
            if login_attempt:
                login_attempt.label = 0
                add_to_trusted_locations(user_id, login_attempt)
                add_to_trusted_devices(user_id, login_attempt.user_agent)
                db.session.commit()
                logger.info(f"Security question verified for user {user.username}")

            user.failed_attempts = 0
            db.session.commit()
            
            session['user_id'] = user_id
            session.pop('is_business_trip', None)
            session.pop('is_initial_training', None)
            session.pop('is_test_mode', None)
            
            return redirect(url_for('dashboard'))
        else:
            flash('Incorrect answer. Please try again.', 'error')
            return render_template('security_question.html')

    return render_template('security_question.html')

def add_to_trusted_locations(user_id, login_attempt):
    if not login_attempt:
        return
    try:
        existing_location = TrustedLocation.query.filter_by(
            user_id=user_id,
            country=login_attempt.country,
            region=login_attempt.region,
            city=login_attempt.city
        ).first()

        # Allow 'Local' to be added as a trusted location
        if not existing_location and all(x not in [None, 'Unknown'] for x in [login_attempt.country, login_attempt.region, login_attempt.city]):
            new_location = TrustedLocation(
                user_id=user_id,
                country=login_attempt.country,
                region=login_attempt.region,
                city=login_attempt.city
            )
            db.session.add(new_location)
            db.session.commit()
            logger.info(f"Added new trusted location: {login_attempt.city}, {login_attempt.region}, {login_attempt.country}")
        else:
            logger.info(f"Location already trusted or invalid: {login_attempt.city}, {login_attempt.region}, {login_attempt.country}")
    except Exception as e:
        logger.error(f"Error adding trusted location: {e}")

def get_client_ip():
    if 'test_ip' in session:
        logger.debug(f"Using test IP: {session['test_ip']}")
        return session['test_ip']
        
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0]
    else:
        return request.remote_addr

def get_geolocation(ip_address):
    if 'test_location' in session:
        test_loc = session['test_location']
        logger.debug(f"Using test location: {test_loc}")
        return (test_loc['country'], test_loc['region'], test_loc['city'])
    
    if ip_address == '127.0.0.1':
        return ('Local', 'Local', 'Local')
                
    try:
        response = requests.get(f'http://ip-api.com/json/{ip_address}')
        data = response.json()
        if data.get('status') == 'success':
            return data.get('country'), data.get('regionName'), data.get('city')
        else:
            return 'Unknown', 'Unknown', 'Unknown'
    except:
        return 'Unknown', 'Unknown', 'Unknown'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_agent = request.form.get('user_agent', request.headers.get('User-Agent', ''))
        user = User.query.filter_by(username=username).first()

        if user:
            if not user.is_active:
                flash('Please confirm your email before logging in.')
                return render_template('login.html')

            if user.is_locked:
                flash('Your account is locked.')
                return render_template('login.html', show_unlock=True, username=username)

            if not check_password_hash(user.password, password):
                user.failed_attempts += 1
                db.session.commit()
                logger.info(f"Failed attempts for user {user.username}: {user.failed_attempts}")

                MAX_FAILED_ATTEMPTS = 5
                if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
                    user.is_locked = True
                    db.session.commit()
                    flash('Your account has been locked due to too many failed attempts.')
                    return render_template('login.html', show_unlock=True, username=username)

                flash('Invalid credentials')
                return render_template('login.html')

            ip_address = get_client_ip()
            country, region, city = get_geolocation(ip_address)
            login_count = LoginAttempt.query.filter_by(user_id=user.id).count()

            if login_count == 0:
                # First login attempt, trust the location and device
                login_attempt = LoginAttempt(
                    user_id=user.id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    login_time=datetime.datetime.now(),
                    login_hour=datetime.datetime.now().hour,
                    login_day=datetime.datetime.now().weekday(),
                    country=country,
                    region=region,
                    city=city,
                    is_trusted_country=1 if country in ['Taiwan', 'Local'] else 0,
                    is_trusted_region=1 if region in ['Taipei', 'Local'] else 0,
                    is_trusted_city=1 if city in ['Taipei', 'Local'] else 0,
                    label=0
                )
                db.session.add(login_attempt)
                add_to_trusted_locations(user.id, login_attempt)
                add_to_trusted_devices(user.id, user_agent)
                db.session.commit()
                session['user_id'] = user.id
                return redirect(url_for('dashboard'))

            current_time = (
                datetime.datetime.fromisoformat(request.form['simulated_time'])
                if 'simulated_time' in request.form
                else datetime.datetime.now()
            )

            prev_attempt = LoginAttempt.query.filter_by(user_id=user.id).order_by(LoginAttempt.login_time.desc()).first()
            time_diff_hours = 0.0
            prev_location = None
            if prev_attempt:
                time_diff_hours = (current_time - prev_attempt.login_time).total_seconds() / 3600
                prev_location = {
                    'city': prev_attempt.city,
                    'region': prev_attempt.region,
                    'country': prev_attempt.country
                }
                logger.info(f"Time difference between logins: {time_diff_hours:.2f} hours")

            current_location = {
                'city': city,
                'region': region,
                'country': country
            }

            risk_results = assess_risk_ml(
                ip_address, 
                user_agent, 
                current_time, 
                country, 
                region, 
                city, 
                user,
                prev_location=prev_location,
                current_location=current_location,
                time_diff_hours=time_diff_hours
            )

            final_risk_score = risk_results['risk_score']
            logger.info(f"Risk score for user {user.username}: {final_risk_score}")

            session['risk_score'] = final_risk_score
            session['base_ml_risk_score'] = risk_results['base_ml_risk_score']
            session['device_change_risk'] = risk_results['device_change_risk']
            session['location_trust_factor'] = risk_results['location_trust_factor']
            session['failed_attempts_factor'] = risk_results['failed_attempts_factor']

            login_attempt = LoginAttempt(
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                login_time=current_time,
                login_hour=current_time.hour,
                login_day=current_time.weekday(),
                country=country if country else 'Unknown',
                region=region if region else 'Unknown',
                city=city if city else 'Unknown',
                is_trusted_country=risk_results.get('is_trusted_country', 0),
                is_trusted_region=risk_results.get('is_trusted_region', 0),
                is_trusted_city=risk_results.get('is_trusted_city', 0),
                label=label_attempt(user.id, ip_address, user_agent, country, region, city)
            )
            db.session.add(login_attempt)
            db.session.commit()

            user.failed_attempts = 0
            db.session.commit()

            if final_risk_score < 0.3:
                session['user_id'] = user.id
                return redirect(url_for('dashboard'))
            elif final_risk_score < 0.6:
                session['user_id'] = user.id
                return redirect(url_for('verify_identity'))
            else:
                session['user_id'] = user.id
                return redirect(url_for('security_question'))

        flash('Invalid credentials')
        return render_template('login.html')

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    user_id = session.get('user_id')
    if not user_id:
        flash('Session expired. Please log in again.')
        return redirect(url_for('login'))

    user = User.query.get_or_404(user_id)
    if not user:
        flash('User not found.')
        return redirect(url_for('login'))

    risk_score = session.get('risk_score', 'N/A')
    base_ml_risk_score = session.get('base_ml_risk_score', 'N/A')
    device_change_risk = session.get('device_change_risk', 'N/A')
    location_trust_factor = session.get('location_trust_factor', 'N/A')
    failed_attempts_factor = session.get('failed_attempts_factor', 'N/A')

    login_attempt = LoginAttempt.query.filter_by(user_id=user_id).order_by(LoginAttempt.id.desc()).first()
    if login_attempt:
        ip_address = login_attempt.ip_address
        country = login_attempt.country if login_attempt.country else 'Unknown'
        region = login_attempt.region if login_attempt.region else 'Unknown'
        city = login_attempt.city if login_attempt.city else 'Unknown'
        user_agent = login_attempt.user_agent if login_attempt.user_agent else 'Unknown'
    else:
        ip_address = 'Unknown'
        country = 'Unknown'
        region = 'Unknown'
        city = 'Unknown'
        user_agent = 'Unknown'

    return render_template(
        'dashboard.html',
        username=user.username,
        risk_score=risk_score,
        base_ml_risk_score=base_ml_risk_score,
        device_change_risk=device_change_risk,
        location_trust_factor=location_trust_factor,
        failed_attempts_factor=failed_attempts_factor,
        ip_address=ip_address,
        country=country,
        region=region,
        city=city,
        user_agent=user_agent
    )

@app.route('/verify_identity', methods=['GET', 'POST'])
def verify_identity():
    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        stored_otp = session.get('otp')
        
        if not stored_otp:
            flash('OTP session expired. Please try again.', 'error')
            return render_template('verify_identity.html')
            
        if entered_otp == stored_otp:
            user_id = session.get('user_id')
            if user_id:
                user = db.session.get(User, user_id)
                login_attempt = LoginAttempt.query.filter_by(user_id=user_id).order_by(LoginAttempt.id.desc()).first()
                
                if login_attempt:
                    login_attempt.label = 0
                    add_to_trusted_locations(user_id, login_attempt)
                    add_to_trusted_devices(user_id, login_attempt.user_agent)
                    db.session.commit()
                    logger.info(f"Verification successful for user {user.username}")

                if user:
                    user.failed_attempts = 0
                    db.session.commit()
                
                session.pop('otp', None)
                session.pop('otp_generated_at', None)
                session.pop('otp_attempts', None)
                session.pop('is_business_trip', None)
                session.pop('is_initial_training', None)
                session.pop('is_test_mode', None)
                
                return redirect(url_for('dashboard'))
        else:
            flash('Incorrect OTP. Please try again.', 'error')
            return render_template('verify_identity.html')
    
    otp_code = str(random.randint(100000, 999999))
    session['otp'] = otp_code
    session['otp_generated_at'] = datetime.datetime.now().isoformat()
    session['otp_attempts'] = 0

    user_id = session.get('user_id')
    if user_id:
        user = User.query.get_or_404(user_id)
        if user:
            msg = Message('Your OTP Code', sender=app.config['MAIL_USERNAME'], recipients=[user.email])
            msg.body = f'Your OTP code is {otp_code}'
            try:
                mail.send(msg)
                logger.info(f"OTP code sent to user {user.username} at {user.email}")
            except Exception as e:
                flash('Failed to send OTP. Please try again.', 'error')
                return render_template('verify_identity.html')

    return render_template('verify_identity.html')

def get_user_typical_hours(user_id):
    attempts = LoginAttempt.query.filter_by(user_id=user_id, label=0).all()
    if not attempts:
        return list(range(24))

    hours = [attempt.login_hour for attempt in attempts]
    from collections import Counter
    hour_counts = Counter(hours)
    avg_frequency = sum(hour_counts.values()) / len(hour_counts) if hour_counts else 0

    typical_hours = [hour for hour, count in hour_counts.items() if count >= 0.25 * avg_frequency]
    if not typical_hours:
        typical_hours = hours
    return typical_hours

def label_attempt(user_id, ip_address, user_agent, country, region, city):
    previous_attempts = LoginAttempt.query.filter_by(user_id=user_id, label=0).all()
    if not previous_attempts:
        return 0  # Default to normal if no history

    trusted_locations = TrustedLocation.query.filter_by(user_id=user_id).all()
    trusted_countries = set(tl.country for tl in trusted_locations)
    trusted_regions = set(tl.region for tl in trusted_locations)
    trusted_cities = set(tl.city for tl in trusted_locations)

    # If the current location is entirely 'Local', treat it as trusted
    if country == 'Local' and region == 'Local' and city == 'Local':
        return 0  # Treat 'Local' as normal

    # Define anomaly only if multiple conditions are met
    anomaly_conditions = [
        country not in trusted_countries,
        region not in trusted_regions,
        city not in trusted_cities,
        user_agent not in [td.user_agent for td in TrustedDevice.query.filter_by(user_id=user_id).all()]
    ]

    # An anomaly is only if at least two conditions are met
    if sum(anomaly_conditions) >= 2:
        return 1
    return 0

def calculate_travel_risk(previous_location, current_location, time_difference_hours):
    if not previous_location or not current_location:
        logger.warning("Previous or current location is None")
        return 0.0, {"error": "One or both locations are None"}

    if any(x in ['Local', 'Unknown', None]
           for loc in [previous_location, current_location]
           for x in loc.values()):
        logger.info("Skipping travel calculation for Local/Unknown locations")
        return 0.0, {"info": "Local or unknown locations"}

    try:
        coords1 = get_cached_coords(
            previous_location['city'],
            previous_location['region'],
            previous_location['country']
        )
        coords2 = get_cached_coords(
            current_location['city'],
            current_location['region'],
            current_location['country']
        )

        if not coords1 or not coords2:
            logger.warning("Could not retrieve coordinates for one or both locations")
            return 0.0, {"error": "Coordinates not found"}

        distance = geodesic(coords1, coords2).miles
        MIN_TIME = 0.016667  # Approximately 1 minute

        if time_difference_hours < MIN_TIME and distance > 0:
            required_speed = distance / MIN_TIME
            return 1.0, {
                "from_location": f"{previous_location['city']}, {previous_location['region']}",
                "to_location": f"{current_location['city']}, {current_location['region']}",
                "distance_miles": round(distance, 2),
                "time_hours": round(time_difference_hours, 3),
                "required_speed_mph": round(required_speed, 2),
                "assessment": f"Suspicious: {distance:.1f} miles in under a minute"
            }

        required_speed = distance / max(time_difference_hours, MIN_TIME)
        travel_details = {
            "from_location": f"{previous_location['city']}, {previous_location['region']}",
            "to_location": f"{current_location['city']}, {current_location['region']}",
            "distance_miles": round(distance, 2),
            "time_hours": round(time_difference_hours, 2),
            "required_speed_mph": round(required_speed, 2)
        }

        if required_speed > 600:
            risk_score = 1.0
            travel_details["assessment"] = "Impossible travel detected"
        elif required_speed > 500:
            risk_score = 0.7
            travel_details["assessment"] = "Suspicious travel speed"
        elif required_speed > 150 and distance < 50:
            risk_score = 0.4
            travel_details["assessment"] = "Fast speed over short distance"
        elif required_speed > 80:
            risk_score = 0.1
            travel_details["assessment"] = "Fast but possible"
        else:
            risk_score = 0.0
            travel_details["assessment"] = "Normal travel distance"

        logger.info(f"Travel risk calculation complete: {travel_details}")
        return risk_score, travel_details

    except Exception as e:
        logger.error(f"Error in travel risk calculation: {e}")
        return 0.0, {"error": str(e)}

def assess_risk_ml(ip_address, user_agent, login_time, country, region, city, user, prev_location=None, current_location=None, time_diff_hours=0.0):
    global MODEL, model_features, encoders

    if not os.path.exists(ENCODERS_PATH) or not os.path.exists(MODEL_PATH) or not os.path.exists(MODEL_FEATURES_PATH):
        logger.warning("Encoders, model, or model features not found, returning default risk assessment")
        return {
            'base_ml_risk_score': 0.3,
            'device_change_risk': 0.0,
            'travel_risk': 0.0,
            'location_trust_factor': 1.0,
            'failed_attempts_factor': 0.0,
            'risk_score': 0.3
        }

    try:
        if MODEL is None:
            MODEL = joblib.load(MODEL_PATH)  # Load the entire pipeline
            encoders = joblib.load(ENCODERS_PATH)
            model_features_dict = joblib.load(MODEL_FEATURES_PATH)
            model_features = model_features_dict['model_features']
            logger.info("Model pipeline and encoders loaded successfully")
    except Exception as e:
        logger.error(f"Failed to load model pipeline or encoders: {e}")
        return {
            'base_ml_risk_score': 0.3,
            'device_change_risk': 0.0,
            'travel_risk': 0.0,
            'location_trust_factor': 1.0,
            'failed_attempts_factor': 0.0,
            'risk_score': 0.3
        }

    previous_attempt = LoginAttempt.query.filter_by(user_id=user.id).order_by(LoginAttempt.login_time.desc()).first()
    trusted_device = TrustedDevice.query.filter_by(user_id=user.id, user_agent=user_agent).first()

    device_change_risk = 0.0
    if previous_attempt and previous_attempt.user_agent != user_agent:
        logger.info("New device detected")
        device_change_risk = 0.5 if not trusted_device else 0.0
        logger.info("Device is trusted" if trusted_device else "Device is not trusted")

    travel_risk, travel_details = (0.0, {})
    if prev_location and current_location:
        travel_risk, travel_details = calculate_travel_risk(prev_location, current_location, time_diff_hours)

    recent_attempts = LoginAttempt.query.filter_by(
        user_id=user.id,
    ).filter(
        LoginAttempt.login_time >= login_time - datetime.timedelta(hours=24)
    ).all()

    failed_attempts_24h = sum(1 for a in recent_attempts if a.label == 1)
    unique_ips_24h = len(set(a.ip_address for a in recent_attempts))
    unique_locations_24h = len(set((a.country, a.region, a.city) for a in recent_attempts))

    typical_hours = get_user_typical_hours(user.id)
    is_typical_hour = 1 if login_time.hour in typical_hours else 0
    time_anomaly = 1 - is_typical_hour

    trusted_locations = TrustedLocation.query.filter_by(user_id=user.id).all()
    trusted_countries = set(tl.country for tl in trusted_locations)
    trusted_regions = set(tl.region for tl in trusted_locations)
    trusted_cities = set(tl.city for tl in trusted_locations)

    is_trusted_country = 1 if country in trusted_countries else 0
    is_trusted_region = 1 if region in trusted_regions else 0
    is_trusted_city = 1 if city in trusted_cities else 0

    # Also consider device trust
    device_is_trusted = 1 if trusted_device else 0

    location_trust = 0.0
    if is_trusted_country:
        location_trust += 0.5
    if is_trusted_region:
        location_trust += 0.3
    if is_trusted_city:
        location_trust += 0.2

    failed_attempts_factor = min(user.failed_attempts * 0.1, 0.3)

    # Derive user_agent_type and encode it
    user_agent_type = categorize_user_agent(user_agent)

    # Encode categorical features
    features = {
        'failed_attempts': user.failed_attempts,
        'failed_attempts_24h': failed_attempts_24h,
        'attempts_24h': len(recent_attempts),
        'unique_ips_24h': unique_ips_24h,
        'unique_locations_24h': unique_locations_24h,
        'is_typical_hour': is_typical_hour,
        'time_anomaly': time_anomaly,
        'hour': login_time.hour,
        'day_of_week': login_time.weekday(),
        'ip_address_encoded': safe_encode('encoder_ip', ip_address),
        'user_agent_encoded': safe_encode('encoder_agent', user_agent),
        'country_encoded': safe_encode('encoder_country', country),
        'region_encoded': safe_encode('encoder_region', region),
        'city_encoded': safe_encode('encoder_city', city),
        'user_agent_type_encoded': safe_encode('encoder_agent_type', user_agent_type),
        'is_trusted_country': is_trusted_country,
        'is_trusted_region': is_trusted_region,
        'is_trusted_city': is_trusted_city
    }

    try:
        X = pd.DataFrame([features])[model_features]
        base_risk = max(MODEL.predict_proba(X)[0][1], 0.01)
        logger.info(f"ML model prediction: {base_risk}")
    except Exception as e:
        logger.error(f"Error in ML prediction: {str(e)}")
        base_risk = 0.3

    logger.info("\nRisk Assessment Details:")
    logger.info(f"Base ML Risk Score: {base_risk}")
    logger.info(f"Device Change Risk: {device_change_risk}")
    logger.info(f"Travel Risk: {travel_risk}")
    logger.info(f"Location Trust Factor: {location_trust}")
    logger.info(f"Failed Attempts Factor: {failed_attempts_factor}")
    logger.info("Location Status:")
    logger.info(f"- Country: {country} ({'trusted' if is_trusted_country else 'not trusted'})")
    logger.info(f"- Region: {region} ({'trusted' if is_trusted_region else 'not trusted'})")
    logger.info(f"- City: {city} ({'trusted' if is_trusted_city else 'not trusted'})")
    logger.info(f"Device Trusted: {'Yes' if device_is_trusted else 'No'}")

    # Adjust the final risk score
    risk_score = base_risk
    risk_score += device_change_risk
    risk_score += travel_risk

    risk_score *= (1 - (location_trust * 0.5))

    # Too many failed attempts should be considered
    risk_score += failed_attempts_factor



    # Ensure risk stays within bounds
    risk_score = max(0.0, min(1.0, risk_score))

    logger.info(f"Final Risk Score: {risk_score}")

    return {
        'base_ml_risk_score': base_risk,
        'device_change_risk': device_change_risk,
        'travel_risk': travel_risk,
        'location_trust_factor': location_trust,
        'failed_attempts_factor': failed_attempts_factor,
        'risk_score': risk_score,
        'is_trusted_country': is_trusted_country,
        'is_trusted_region': is_trusted_region,
        'is_trusted_city': is_trusted_city
    }

def prepare_and_train_model():
    global MODEL, model_features, encoders

    attempts = LoginAttempt.query.all()
    if not attempts:
        logger.warning("No login attempts found for training, skipping model training.")
        return

    data = []
    for attempt in attempts:
        user = db.session.get(User, attempt.user_id)
        if not user:
            continue

        historical_attempts = LoginAttempt.query.filter(
            LoginAttempt.user_id == user.id,
            LoginAttempt.login_time < attempt.login_time,
            LoginAttempt.login_time >= attempt.login_time - datetime.timedelta(hours=24)
        ).all()

        failed_attempts_24h = sum(1 for a in historical_attempts if a.label == 1)
        unique_ips_24h = len(set(a.ip_address for a in historical_attempts))
        unique_locations_24h = len(set((a.country, a.region, a.city) for a in historical_attempts))

        typical_hours = get_user_typical_hours(user.id)
        is_typical_hour = 1 if attempt.login_hour in typical_hours else 0

        data.append({
            'failed_attempts': user.failed_attempts,
            'failed_attempts_24h': failed_attempts_24h,
            'attempts_24h': len(historical_attempts),
            'unique_ips_24h': unique_ips_24h,
            'unique_locations_24h': unique_locations_24h,
            'is_typical_hour': is_typical_hour,
            'time_anomaly': 1 - is_typical_hour,
            'hour': attempt.login_hour,
            'day_of_week': attempt.login_day,
            'ip_address': attempt.ip_address if attempt.ip_address else 'Unknown',
            'user_agent': attempt.user_agent if attempt.user_agent else 'Unknown',
            'country': attempt.country if attempt.country else 'Unknown',
            'region': attempt.region if attempt.region else 'Unknown',
            'city': attempt.city if attempt.city else 'Unknown',
            'is_trusted_country': attempt.is_trusted_country,
            'is_trusted_region': attempt.is_trusted_region,
            'is_trusted_city': attempt.is_trusted_city,
            'label': attempt.label
        })

    if not data:
        logger.warning("No valid data rows to train on, skipping model training.")
        return

    df = pd.DataFrame(data)

    # Derive user_agent_type
    df['user_agent_type'] = df['user_agent'].apply(categorize_user_agent)

    # Define categorical features
    categorical_features = ['ip_address', 'user_agent', 'country', 'region', 'city', 'user_agent_type']
    
    # Initialize encoders with consistent keys
    encoders = {}
    encoder_key_map = {
        'ip_address': 'encoder_ip',
        'user_agent': 'encoder_agent',
        'country': 'encoder_country',
        'region': 'encoder_region',
        'city': 'encoder_city',
        'user_agent_type': 'encoder_agent_type'
    }
    for feature in categorical_features:
        encoder = LabelEncoder()
        # Fit on all possible values including 'Unknown'
        df[feature] = df[feature].fillna('Unknown')
        df[f'{feature}_encoded'] = encoder.fit_transform(df[feature])
        encoders[encoder_key_map[feature]] = encoder  # Use mapped keys

    # Define model features including trust factors
    model_features = [
        'failed_attempts',
        'failed_attempts_24h',
        'attempts_24h',
        'unique_ips_24h',
        'unique_locations_24h',
        'is_typical_hour',
        'time_anomaly',
        'hour',
        'day_of_week',
        'ip_address_encoded',
        'user_agent_encoded',
        'country_encoded',
        'region_encoded',
        'city_encoded',
        'user_agent_type_encoded',
        'is_trusted_country',
        'is_trusted_region',
        'is_trusted_city'
    ]

    X = df[model_features]
    y = df['label']

    # Check class balance
    class_counts = y.value_counts()
    logger.info(f"Class distribution before SMOTE: {class_counts.to_dict()}")

    # Apply SMOTE to handle class imbalance (if necessary)
    if class_counts.min() < 50:  # Arbitrary threshold; adjust as needed
        smote = SMOTE(random_state=42)
        X_balanced, y_balanced = smote.fit_resample(X, y)
        logger.info(f"Class distribution after SMOTE: {pd.Series(y_balanced).value_counts().to_dict()}")
    else:
        X_balanced, y_balanced = X, y

    # Split the data
    X_train, X_val, y_train, y_val = train_test_split(
        X_balanced, y_balanced, test_size=0.2, random_state=42, stratify=y_balanced
    )

    # Define the pipeline
    pipeline = Pipeline([
        ('scaler', StandardScaler()),
        ('gbm', GradientBoostingClassifier(random_state=42))
    ])

    # Define hyperparameter distributions
    param_dist = {
        'gbm__n_estimators': randint(100, 500),
        'gbm__max_depth': randint(3, 10),
        'gbm__learning_rate': uniform(0.01, 0.2),
        'gbm__subsample': uniform(0.7, 0.3)
    }

    # Perform randomized search
    search = RandomizedSearchCV(
        pipeline,
        param_distributions=param_dist,
        n_iter=20,
        scoring='f1',
        cv=3,
        random_state=42,
        verbose=1,
        n_jobs=-1
    )

    # Fit the model
    search.fit(X_train, y_train)

    logger.info(f"Best parameters found: {search.best_params_}")
    logger.info(f"Best cross-validation F1 score: {search.best_score_:.4f}")

    # Evaluate on validation set
    y_pred = search.predict(X_val)
    logger.info(f"Validation Accuracy: {accuracy_score(y_val, y_pred):.4f}")
    logger.info(f"Validation F1 Score: {search.score(X_val, y_val):.4f}")
    logger.info(f"Classification Report:\n{classification_report(y_val, y_pred)}")

    # Save the entire pipeline
    best_pipeline = search.best_estimator_

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(best_pipeline, MODEL_PATH)  # Save the entire pipeline
    joblib.dump(encoders, ENCODERS_PATH)

    # Save model features
    joblib.dump({'model_features': model_features}, MODEL_FEATURES_PATH)

    logger.info("Model training completed successfully with improvements.")

def init_model():
    global MODEL, model_features, encoders
    try:
        if os.path.exists(MODEL_PATH) and os.path.exists(ENCODERS_PATH) and os.path.exists(MODEL_FEATURES_PATH):
            MODEL = joblib.load(MODEL_PATH)
            encoders = joblib.load(ENCODERS_PATH)
            model_features_dict = joblib.load(MODEL_FEATURES_PATH)
            model_features = model_features_dict['model_features']
            logger.info("Model pipeline and encoders loaded successfully")
        else:
            logger.info("No existing model or encoders found, training a new one...")
            prepare_and_train_model()
    except Exception as e:
        logger.error(f"Error loading model or encoders: {e}")
        prepare_and_train_model()

def generate_synthetic_attempts(num_samples):
    synthetic_data = []
    common_user_agents = ['default_device', 'new_device']
    user_ids = [1, 2, 3, 4, 5]  # Introduce multiple users
    
    for _ in range(num_samples):
        # Randomly select a user
        user_id = random.choice(user_ids)
        
        # Decide if this attempt is normal or anomalous (80% normal, 20% anomalous)
        is_anomalous = 1 if random.random() < 0.2 else 0

        if is_anomalous:
            # Generate anomalous attempt
            # Randomly decide if the anomaly is due to location or user agent or both
            anomaly_type = random.choice(['location', 'user_agent', 'both'])
            if anomaly_type == 'location':
                country = random.choice(['Japan', 'Singapore', 'Unknown'])  # Untrusted locations
                region = 'Unknown'
                city = 'Unknown'
                user_agent = random.choice(common_user_agents)
            elif anomaly_type == 'user_agent':
                country = 'Taiwan'
                region = 'Taipei'
                city = 'Taipei'
                user_agent = 'unknown_device'
            else:  # both
                country = random.choice(['Japan', 'Singapore', 'Unknown'])
                region = 'Unknown'
                city = 'Unknown'
                user_agent = 'unknown_device'
            
            hour = random.choice([random.randint(0, 5), random.randint(20, 23)])  # Unusual hours
            is_typical_hour = 0
            failed_attempts = random.randint(3, 5)
            failed_attempts_24h = failed_attempts + random.randint(1, 3)
            unique_ips_24h = random.randint(3, 5)
            unique_locations_24h = random.randint(3, 5)
            is_trusted_country = 0  # Untrusted
            is_trusted_region = 0
            is_trusted_city = 0
        else:
            # Generate normal attempt
            # Including possible 'Local' logins as trusted
            location_type = random.choice(['trusted', 'local'])
            if location_type == 'trusted':
                country = 'Taiwan'
                region = 'Taipei'
                city = 'Taipei'
            else:
                country = 'Local'
                region = 'Local'
                city = 'Local'
            user_agent = 'default_device'
            hour = random.choice([9, 10, 11, 14, 15, 16])  # Typical office hours
            is_typical_hour = 1
            failed_attempts = random.randint(0, 2)
            failed_attempts_24h = failed_attempts
            unique_ips_24h = random.randint(1, 2)
            unique_locations_24h = random.randint(1, 2)
            is_trusted_country = 1  # Trusted
            is_trusted_region = 1
            is_trusted_city = 1

        # Build sample
        sample = {
            'user_id': user_id,
            'ip_address': f'192.168.{random.randint(0, 255)}.{random.randint(1, 255)}',
            'user_agent': user_agent,
            'hour': hour,
            'day_of_week': random.randint(0, 6),
            'is_typical_hour': is_typical_hour,
            'country': country,
            'region': region,
            'city': city,
            'failed_attempts': failed_attempts,
            'attempts_24h': max(failed_attempts_24h, 1),
            'failed_attempts_24h': failed_attempts_24h,
            'unique_ips_24h': unique_ips_24h,
            'unique_locations_24h': unique_locations_24h,
            'is_trusted_country': is_trusted_country,  # Set new fields
            'is_trusted_region': is_trusted_region,
            'is_trusted_city': is_trusted_city,
            'time_anomaly': 1 - is_typical_hour,
            'label': is_anomalous
        }
        synthetic_data.append(sample)
    
    return synthetic_data


def schedule_model_retraining():
    scheduler = BackgroundScheduler()
    scheduler.add_job(func=prepare_and_train_model, trigger="interval", minutes=5)
    scheduler.start()

@app.route('/test_location', methods=['POST'])
def set_test_location():
    data = request.get_json()
    session['test_ip'] = data.get('ip', '1.1.1.1')
    session['test_location'] = {
        'country': data.get('country', 'Test Country'),
        'region': data.get('region', 'Test Region'),
        'city': data.get('city', 'Test City')
    }
    return jsonify({'status': 'success'})

@app.route('/check_records')
def check_records():
    user = User.query.filter_by(username='carey').first()
    if not user:
        return "User not found"
    
    attempts = LoginAttempt.query.filter_by(user_id=user.id).all()
    trusted = TrustedLocation.query.filter_by(user_id=user.id).all()
    
    output = []
    output.append("Login Attempts:")
    for attempt in attempts:
        output.append(f"Time: {attempt.login_time}, Location: {attempt.country}, {attempt.region}, {attempt.city}")
    
    output.append("\nTrusted Locations:")
    for location in trusted:
        output.append(f"Location: {location.country}, {location.region}, {location.city}")
    
    return "<br>".join(output)

@app.route('/set_test_mode', methods=['POST'])
def set_test_mode():
    session['is_test_mode'] = True
    return 'OK'

@app.route('/reset_login_times')
def reset_login_times():
    try:
        current_time = datetime.datetime.now()
        LoginAttempt.query.update({LoginAttempt.login_time: current_time})
        db.session.commit()
        return 'Login times reset to current time'
    except Exception as e:
        db.session.rollback()
        return f'Error resetting login times: {str(e)}'

def add_to_trusted_devices(user_id, user_agent):
    if not user_agent:
        return
    is_test = session.get('is_test_mode', False)
    if is_test:
        return
    existing_device = TrustedDevice.query.filter_by(
        user_id=user_id,
        user_agent=user_agent
    ).first()
    if not existing_device:
        logger.info(f"Adding new trusted device for user {user_id}")
        new_device = TrustedDevice(user_id=user_id, user_agent=user_agent)
        db.session.add(new_device)
        db.session.commit()
        logger.info("Device added successfully")

def get_cached_coords(city, region, country):
    location_key = f"{city}, {region}, {country}"
    if location_key in LOCATION_CACHE:
        return LOCATION_CACHE[location_key]
    
    if 'Local' in [city, region, country] or 'Unknown' in [city, region, country]:
        return None
        
    try:
        location_strings = [
            f"{city}, {region}, {country}",
            f"{city}, {country}",
            f"{region}, {country}",
            country
        ]
        
        for loc_str in location_strings:
            try:
                location = geolocator.geocode(loc_str, timeout=10)
                if location:
                    coords = (location.latitude, location.longitude)
                    LOCATION_CACHE[location_key] = coords
                    logger.info(f"Retrieved coordinates for {loc_str}: {coords}")
                    return coords
                time.sleep(1)  # To respect usage limits
            except (GeocoderTimedOut, GeocoderUnavailable) as e:
                logger.warning(f"Geocoding failed for {loc_str}: {e}")
                continue
                
        logger.error(f"Could not find coordinates for {location_key}")
        return None
    except Exception as e:
        logger.error(f"Error in get_cached_coords: {e}")
        return None

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.')
    return redirect(url_for('login'))

@app.route('/initialize_data', methods=['POST'])
def initialize_data():
    try:
        synthetic_data = generate_synthetic_attempts(2000)
        
        for entry in synthetic_data:
            user = db.session.get(User, entry['user_id'])
            if not user:
                user = User(
                    id=entry['user_id'],
                    username=f'user_{entry["user_id"]}',
                    password=generate_password_hash('password123'),
                    email=f'user_{entry["user_id"]}@example.com',
                    security_question='What is your favorite color?',
                    security_answer=generate_password_hash('blue'),
                    is_active=True
                )
                db.session.add(user)
            
            login_attempt = LoginAttempt(
                user_id=entry['user_id'],
                ip_address=entry['ip_address'],
                user_agent=entry['user_agent'],
                login_time=datetime.datetime.now() - datetime.timedelta(days=random.randint(0, 30), hours=random.randint(0,23)),
                login_hour=entry['hour'],
                login_day=entry['day_of_week'],
                country=entry['country'],
                region=entry['region'],
                city=entry['city'],
                is_trusted_country=entry['is_trusted_country'],
                is_trusted_region=entry['is_trusted_region'],
                is_trusted_city=entry['is_trusted_city'],
                label=entry['label']
            )
            db.session.add(login_attempt)
            
            if entry['label'] == 0:
                existing_location = TrustedLocation.query.filter_by(
                    user_id=entry['user_id'],
                    country=entry['country'],
                    region=entry['region'],
                    city=entry['city']
                ).first()
                
                if not existing_location:
                    trusted_location = TrustedLocation(
                        user_id=entry['user_id'],
                        country=entry['country'],
                        region=entry['region'],
                        city=entry['city']
                    )
                    db.session.add(trusted_location)
        
        db.session.commit()
        
        # Retrain once after initialization
        prepare_and_train_model()
        
        return jsonify({'status': 'success', 'message': 'Data initialized and model trained'})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error initializing data: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Only train if no model exists. If you want fewer retrains, remove unneeded calls.
        if not os.path.exists(MODEL_PATH):
            with app.test_client() as client:
                client.post('/initialize_data')
        init_model()
        #schedule_model_retraining()
    app.run(debug=True, host='0.0.0.0', port=5000)
