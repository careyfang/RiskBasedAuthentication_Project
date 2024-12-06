from flask import Flask, render_template, redirect, url_for, request, session, flash
from models import db, User, LoginAttempt, TrustedLocation, TrustedDevice
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
from random import randint
import requests
import pandas as pd
import numpy as np
import os
from sklearn.preprocessing import LabelEncoder
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from dotenv import load_dotenv
from sklearn.ensemble import GradientBoostingClassifier
import logging
from imblearn.over_sampling import SMOTE
import random
from apscheduler.schedulers.background import BackgroundScheduler
from sklearn.ensemble import IsolationForest
import joblib
from geopy.distance import geodesic
from geopy.geocoders import Nominatim
from config.test_locations import get_cached_coords, LOCATION_CACHE

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rba.db'

# Email configuration for OTP
load_dotenv()
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Replace with your SMTP server
app.config['MAIL_PORT'] = 587  # Replace with your mail server port
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')

db.init_app(app)
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)

# Global variables for the model and encoders
model = None
encoder_ip = LabelEncoder()
encoder_agent = LabelEncoder()
encoder_country = LabelEncoder()
encoder_region = LabelEncoder()
encoder_city = LabelEncoder()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def safe_encode(encoder, value):
    """Safely encode values, handling unknown categories"""
    try:
        return encoder.transform([value])[0]
    except:
        # Return the encoded value for 'Unknown' or 0 if that fails
        try:
            return encoder.transform(['Unknown'])[0]
        except:
            return 0

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/retrain_model')
def retrain_model():
    prepare_and_train_model()
    return 'Model retrained with new data.'

@app.route('/unlock_account', methods=['GET', 'POST'])
def unlock_account():
    if request.method == 'POST':
        # Check if the form is for username submission or security answer
        if 'username' in request.form:
            username = request.form['username']
            user = User.query.filter_by(username=username).first()
            if user:
                # Store the username in session to use in the next step
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
                # Unlock the account
                user.failed_attempts = 0
                user.is_locked = False
                db.session.commit()
                flash('Your account has been unlocked. You can now log in.')
                # Remove the username from session
                session.pop('unlock_username', None)
                return redirect(url_for('login'))
            else:
                flash('Incorrect security answer. Please try again.')
                return render_template('security_question.html', question=user.security_question)
    return render_template('unlock_account.html')


@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=3600)  # Token expires in 1 hour
    except Exception as e:
        print(f"Email confirmation error: {e}")
        return 'The confirmation link is invalid or has expired.', 400

    user = User.query.filter_by(email=email).first()
    if user:
        user.is_active = True  # You need to add this field to your User model
        db.session.commit()
        return render_template('email_confirmed.html')
    else:
        return 'User not found.', 404

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get form data
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        email = request.form['email']
        security_question = request.form['security_question']
        security_answer = generate_password_hash(request.form['security_answer'])

        # Validate password confirmation
        if password != confirm_password:
            flash('Passwords do not match. Please try again.')
            return render_template('register.html')

        # Hash the password
        password_hash = generate_password_hash(password)

        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose another one.')
            return render_template('register.html')

        # Create user but don't commit yet
        new_user = User(
            username=username,
            password=password_hash,
            email=email,
            security_question=security_question,
            security_answer=security_answer
        )
        db.session.add(new_user)
        db.session.flush()  # Get new_user.id without committing

        # Generate email verification token
        token = serializer.dumps(email, salt='email-confirm')

        # Send verification email
        confirm_url = url_for('confirm_email', token=token, _external=True)
        msg = Message('Confirm Your Email', sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = f'Please click the link to confirm your email: {confirm_url}'
        try:
            mail.send(msg)
            print(f"Confirmation email sent to {email}")
            db.session.commit()
        except Exception as e:
            print(f"Failed to send confirmation email: {e}")
            db.session.rollback()
            return 'Failed to send confirmation email. Please try again later.', 500

        # Inform the user to check their email
        return 'A confirmation email has been sent. Please check your email to complete registration.'

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

        entered_answer = request.form.get('security_answer')
        if entered_answer and entered_answer.lower() == user.security_answer.lower():
            # Mark the latest attempt as legitimate
            login_attempt = LoginAttempt.query.filter_by(user_id=user_id).order_by(LoginAttempt.id.desc()).first()
            if login_attempt:
                login_attempt.label = 0
                add_to_trusted_locations(user_id, login_attempt)
                # Add device to trusted devices
                add_to_trusted_devices(user_id, login_attempt.user_agent)
                db.session.commit()
                prepare_and_train_model()

            return redirect(url_for('dashboard'))
        else:
            flash('Incorrect answer. Please try again.', 'error')
            return render_template('security_question.html')

    return render_template('security_question.html')

def add_to_trusted_locations(user_id, login_attempt):
    """Add location to trusted locations after successful verification"""
    # Only add trusted locations if not in test mode and during training
    is_test = session.get('is_test_mode', False)
    is_training = session.get('is_initial_training', False)
    should_trust = is_training and not is_test

    if should_trust and login_attempt:
        existing_location = TrustedLocation.query.filter_by(
            user_id=user_id,
            country=login_attempt.country,
            region=login_attempt.region,
            city=login_attempt.city
        ).first()

        if not existing_location:
            new_location = TrustedLocation(
                user_id=user_id,
                country=login_attempt.country,
                region=login_attempt.region,
                city=login_attempt.city
            )
            db.session.add(new_location)

def get_client_ip():
    # For testing: check if there's a test IP in session
    if 'test_ip' in session:
        print(f"Using test IP: {session['test_ip']}")  # Debug log
        return session['test_ip']
        
    if request.headers.getlist("X-Forwarded-For"):
        ip = request.headers.getlist("X-Forwarded-For")[0]
    else:
        ip = request.remote_addr
    return ip

def get_geolocation(ip_address):
    # For testing: check if there's test geolocation data in session
    if 'test_location' in session:
        test_loc = session['test_location']
        print(f"Using test location: {test_loc}")  # Debug log
        return (test_loc['country'], test_loc['region'], test_loc['city'])
    
    # Handle localhost specially
    if ip_address == '127.0.0.1':
        return ('Local', 'Local', 'Local')
                
    try:
        response = requests.get(f'http://ip-api.com/json/{ip_address}')
        data = response.json()
        if data['status'] == 'success':
            return data['country'], data['regionName'], data['city']
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
                print(f"Failed attempts for user {user.username}: {user.failed_attempts}")

                MAX_FAILED_ATTEMPTS = 5
                if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
                    user.is_locked = True
                    db.session.commit()
                    flash('Your account has been locked due to too many failed attempts.')
                    return render_template('login.html', show_unlock=True, username=username)

                flash('Invalid credentials')
                return render_template('login.html')

            # Get contextual data
            ip_address = get_client_ip()
            country, region, city = get_geolocation(ip_address)

            # Use simulated time if provided, otherwise use current time
            current_time = (
                datetime.datetime.fromisoformat(request.form['simulated_time'])
                if 'simulated_time' in request.form
                else datetime.datetime.now()
            )

            # Get previous login attempt for time difference
            prev_attempt = LoginAttempt.query.filter_by(user_id=user.id).order_by(LoginAttempt.login_time.desc()).first()
            
            # Calculate time difference and get previous location
            time_diff_hours = 0.0
            prev_location = None
            if prev_attempt:
                time_diff_hours = (current_time - prev_attempt.login_time).total_seconds() / 3600
                prev_location = {
                    'city': prev_attempt.city,
                    'region': prev_attempt.region,
                    'country': prev_attempt.country
                }
                print(f"Time difference between logins: {time_diff_hours:.2f} hours")

            # Current location
            current_location = {
                'city': city,
                'region': region,
                'country': country
            }

            # Perform risk assessment with location and time data
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

            # Extract the final risk score
            final_risk_score = risk_results['risk_score']
            print(f"Risk score for user {user.username}: {final_risk_score}")

            # Store all metrics individually in the session
            session['risk_score'] = final_risk_score
            session['base_ml_risk_score'] = risk_results['base_ml_risk_score']
            session['device_change_risk'] = risk_results['device_change_risk']
            session['location_trust_factor'] = risk_results['location_trust_factor']
            session['failed_attempts_factor'] = risk_results['failed_attempts_factor']

            # Store login attempt with simulated time
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

    # Retrieve risk metrics from the session
    risk_score = session.get('risk_score', 'N/A')
    base_ml_risk_score = session.get('base_ml_risk_score', 'N/A')
    device_change_risk = session.get('device_change_risk', 'N/A')
    location_trust_factor = session.get('location_trust_factor', 'N/A')
    failed_attempts_factor = session.get('failed_attempts_factor', 'N/A')

    # Retrieve last login attempt details for IP, location, device if you want (already in code)
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
        if 'otp' in session and entered_otp == session['otp']:
            user_id = session.get('user_id')
            if user_id:
                user = db.session.get(User, user_id)
                login_attempt = LoginAttempt.query.filter_by(user_id=user_id).order_by(LoginAttempt.id.desc()).first()
                
                if login_attempt:
                    login_attempt.label = 0  # Mark as legitimate
                    
                    # Check if this is one of the user's first logins
                    login_count = LoginAttempt.query.filter_by(
                        user_id=user_id,
                        label=0
                    ).count()
                    
                    # Trust location after successful verification unless it's a test
                    is_test = session.get('is_test_mode', False)
                    should_trust = not is_test  # Trust unless explicitly in test mode
                    
                    if should_trust and all(x not in ['Unknown', 'None'] 
                                          for x in [login_attempt.country, 
                                                  login_attempt.region, 
                                                  login_attempt.city]):
                        
                        existing_location = TrustedLocation.query.filter_by(
                            user_id=user_id,
                            country=login_attempt.country,
                            region=login_attempt.region,
                            city=login_attempt.city
                        ).first()

                        if not existing_location:
                            print(f"Adding trusted location: {login_attempt.country}, {login_attempt.region}, {login_attempt.city}")
                            new_location = TrustedLocation(
                                user_id=user_id,
                                country=login_attempt.country,
                                region=login_attempt.region,
                                city=login_attempt.city
                            )
                            db.session.add(new_location)
                    
                    # Add device to trusted devices
                    add_to_trusted_devices(user_id, login_attempt.user_agent)
                    
                    db.session.commit()
                    prepare_and_train_model()

                # Complete login
                session['user_id'] = user_id
                session.pop('otp', None)
                session.pop('otp_generated_at', None)
                session.pop('otp_attempts', None)
                session.pop('is_business_trip', None)
                session.pop('is_initial_training', None)
                session.pop('is_test_mode', None)

                return redirect(url_for('dashboard'))
    else:
        # Generate an OTP code and store it in the session
        otp_code = str(randint(100000, 999999))
        session['otp'] = otp_code
        session['otp_generated_at'] = datetime.datetime.now().isoformat()
        session['otp_attempts'] = 0

        # Send OTP via email
        user_id = session.get('user_id')
        user = User.query.get_or_404(user_id)
        if user:
            msg = Message('Your OTP Code', sender=app.config['MAIL_USERNAME'], recipients=[user.email])
            msg.body = f'Your OTP code is {otp_code}'
            try:
                mail.send(msg)
                print(f"OTP code sent to user {user.username} at {user.email}")
            except Exception as e:
                print(f"Failed to send OTP email: {e}")
                return f'Failed to send OTP. Error: {e}', 500
        else:
            return 'User not found.', 404

        return render_template('verify_identity.html')

def get_user_typical_hours(user_id):
    # Fetch legitimate login attempts for the user
    attempts = LoginAttempt.query.filter_by(user_id=user_id, label=0).all()
    if not attempts:
        return list(range(24))  # If no data, assume all hours are typical

    # Collect login hours and their frequencies
    hours = [attempt.login_hour for attempt in attempts]
    from collections import Counter
    hour_counts = Counter(hours)

    # Calculate the average frequency
    avg_frequency = sum(hour_counts.values()) / len(hour_counts) if hour_counts else 0

    # Consider an hour "typical" if it occurs at least 25% of the average frequency
    typical_hours = [hour for hour, count in hour_counts.items() if count >= 0.25 * avg_frequency]

    if not typical_hours:
        typical_hours = hours  # If no hour meets the threshold, use all observed hours

    return typical_hours

def label_attempt(user_id, ip_address, user_agent, country, region, city):
    previous_attempts = LoginAttempt.query.filter_by(user_id=user_id, label=0).all()
    if not previous_attempts:
        return 0  # First login attempt is considered legitimate

    # Get user's trusted locations
    trusted_locations = TrustedLocation.query.filter_by(user_id=user_id).all()
    trusted_countries = set(loc.country for loc in trusted_locations)
    trusted_regions = set(loc.region for loc in trusted_locations)
    trusted_cities = set(loc.city for loc in trusted_locations)

    # Check if current location is trusted
    location_trusted = (country in trusted_countries and 
                       region in trusted_regions and 
                       city in trusted_cities)

    # Previous locations
    previous_countries = set(a.country for a in previous_attempts)
    previous_regions = set(a.region for a in previous_attempts)
    previous_cities = set(a.city for a in previous_attempts)

    # Consider attempt anomalous if location is new
    if (country not in previous_countries or 
        region not in previous_regions or 
        city not in previous_cities):
        return 1  # Mark as anomalous

    return 0  # Mark as legitimate

def calculate_travel_risk(previous_location, current_location, time_difference_hours):
    # Check for None locations before attempting to use them
    if previous_location is None or current_location is None:
        logger.error("Previous or current location is None, cannot calculate travel risk.")
        return 0.0, {"error": "One or both locations are None."}

    # Check for 'Local', 'Unknown', or 'None' values in the location data
    if any(x in ['Local', 'Unknown', 'None']
           for loc in [previous_location, current_location]
           for x in loc.values()):
        return 0.0, {"error": "Local or unknown locations - skipping travel calculation"}

    try:
        coords1 = get_cached_coords(previous_location['city'],
                                    previous_location['region'],
                                    previous_location['country'])
        coords2 = get_cached_coords(current_location['city'],
                                    current_location['region'],
                                    current_location['country'])
        
        if coords1 is None or coords2 is None:
            logger.error("Coordinates could not be retrieved, cannot calculate travel risk.")
            return 0.0, {"error": "Coordinates not found for given locations."}

        distance = geodesic(coords1, coords2).miles
        MIN_TIME = 0.016667  # 1 minute in hours

        # If time difference is too small but locations differ
        if time_difference_hours < MIN_TIME and distance > 0:
            required_speed = distance / MIN_TIME
            return 1.0, {
                "from_location": f"{previous_location['city']}, {previous_location['region']}",
                "to_location": f"{current_location['city']}, {current_location['region']}",
                "distance_miles": round(distance, 2),
                "time_hours": round(time_difference_hours, 3),
                "required_speed_mph": round(required_speed, 2),
                "assessment": f"Suspicious: {distance:.1f} miles traveled in less than a minute"
            }

        # Normal speed calculation
        required_speed = distance / max(time_difference_hours, MIN_TIME)
        travel_details = {
            "from_location": f"{previous_location['city']}, {previous_location['region']}",
            "to_location": f"{current_location['city']}, {current_location['region']}",
            "from_coords": f"({coords1[0]}, {coords1[1]})",
            "to_coords": f"({coords2[0]}, {coords2[1]})",
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
    # Get the previous attempt to determine device change
    previous_attempt = LoginAttempt.query.filter_by(user_id=user.id).order_by(LoginAttempt.login_time.desc()).first()

    # Check device trust
    trusted_device = TrustedDevice.query.filter_by(
        user_id=user.id,
        user_agent=user_agent
    ).first()

    device_change_risk = 0.0
    if previous_attempt and previous_attempt.user_agent != user_agent:
        logger.info("New device detected")
        if not trusted_device:
            device_change_risk = 0.3
            logger.info("Device is not trusted")
        else:
            logger.info("Device is trusted")

    # Compute travel risk once
    if prev_location is None or current_location is None:
        logger.info("Cannot calculate travel risk because one or both locations are None.")
        travel_risk = 0.0
        travel_details = {"error": "One or both locations are None."}
    else:
        travel_risk, travel_details = calculate_travel_risk(prev_location, current_location, time_diff_hours)
        if travel_risk > 0:
            logger.info("Travel Analysis:")
            logger.info(f"Previous location: {prev_location['city']}, {prev_location['region']}, {prev_location['country']}")
            logger.info(f"Current location: {current_location['city']}, {current_location['region']}, {current_location['country']}")
            logger.info(f"Time difference: {time_diff_hours:.2f} hours")
            logger.info(f"Travel details: {travel_details}")
            logger.info(f"Travel risk score: {travel_risk}")

    # Check if user is new (few attempts)
    user_attempts = LoginAttempt.query.filter_by(user_id=user.id).count()
    if user_attempts < 1:
        # Simplified risk assessment for new users
        risk_score = 0.0
        # Basic checks for new users
        # Increase risk if location untrusted
        trusted_locations = TrustedLocation.query.filter_by(user_id=user.id).all()
        trusted_countries = set(tl.country for tl in trusted_locations)

        if country not in trusted_countries:
            risk_score += 0.2
        if user.failed_attempts > 0:
            risk_score += 0.1 * user.failed_attempts
        if login_time.hour not in range(6, 22):
            risk_score += 0.1

        risk_score = min(risk_score, 0.6)
        logger.info(f"Using simplified risk assessment for new user: {risk_score}")
        return {
            'base_ml_risk_score': 'N/A',
            'device_change_risk': device_change_risk,
            'location_trust_factor': 0.0,  # Unknown at this early stage
            'failed_attempts_factor': 0.0,
            'risk_score': risk_score
        }

    # Calculate recent attempts stats
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

    # Location trust calculation
    trusted_locations = TrustedLocation.query.filter_by(user_id=user.id).all()
    trusted_countries = set(tl.country for tl in trusted_locations)
    trusted_regions = set(tl.region for tl in trusted_locations)
    trusted_cities = set(tl.city for tl in trusted_locations)

    is_trusted_country = 1 if country in trusted_countries else 0
    is_trusted_region = 1 if region in trusted_regions else 0
    is_trusted_city = 1 if city in trusted_cities else 0

    location_trust = 0.0
    if is_trusted_country:
        location_trust += 0.5
    if is_trusted_region:
        location_trust += 0.3
    if is_trusted_city:
        location_trust += 0.2

    # Prepare input data
    input_data = pd.DataFrame({
        'failed_attempts': [user.failed_attempts],
        'failed_attempts_24h': [failed_attempts_24h],
        'attempts_24h': [len(recent_attempts)],
        'unique_ips_24h': [unique_ips_24h],
        'unique_locations_24h': [unique_locations_24h],
        'is_typical_hour': [is_typical_hour],
        'time_anomaly': [time_anomaly],
        'hour': [login_time.hour],
        'day_of_week': [login_time.weekday()],
        'ip_address_encoded': [safe_encode(encoder_ip, ip_address)],
        'user_agent_encoded': [safe_encode(encoder_agent, user_agent)],
        'country_encoded': [safe_encode(encoder_country, country)],
        'region_encoded': [safe_encode(encoder_region, region)],
        'city_encoded': [safe_encode(encoder_city, city)],
        'is_trusted_country': [is_trusted_country],
        'is_trusted_region': [is_trusted_region],
        'is_trusted_city': [is_trusted_city]
    })

    # Ensure model is not None before prediction
    if model is None:
        logger.error("Model is None. Ensure that the model is loaded or trained before prediction.")
        return {
            'base_ml_risk_score': 'N/A',
            'device_change_risk': 'N/A',
            'location_trust_factor': 'N/A',
            'failed_attempts_factor': 'N/A',
            'risk_score': 0.5
        }

    try:
        # Get base risk score from ML model
        risk_probs = model.predict_proba(input_data)[0]
        anomalous_index = list(model.classes_).index(1)
        base_risk_score = risk_probs[anomalous_index]

        # Apply device change risk
        if device_change_risk > 0:
            risk_score = base_risk_score * (1 + device_change_risk) + (device_change_risk * 0.2)
        else:
            risk_score = base_risk_score

        # Failed attempts factor
        failed_attempts_factor = min(user.failed_attempts / 4.0, 1.0)

        # Adjust based on location trust
        if location_trust == 0:
            risk_score = max(0.4, risk_score)
        elif location_trust < 1.0:
            base_untrusted_risk = 0.2
            untrusted_factor = 1.0 - location_trust
            adjustment = (untrusted_factor * 0.3 * (1 + risk_score)) + base_untrusted_risk
            risk_score = risk_score + adjustment
        else:
            risk_score *= 0.5

        # Add failed attempts influence
        risk_score += (failed_attempts_factor * 0.2)

        # Adjust for travel risk if significant
        if travel_risk > 0.7:
            risk_score = max(risk_score, 0.8)

        # Bounds on risk_score
        risk_score = max(0.1, min(0.9, risk_score))

        logger.info(f"\nRisk Assessment Details:")
        logger.info(f"Base ML Risk Score: {base_risk_score}")
        logger.info(f"Device Change Risk: {device_change_risk}")
        logger.info(f"Location Trust Factor: {location_trust}")
        logger.info(f"Failed Attempts Factor: {failed_attempts_factor}")
        logger.info(f"Final Risk Score: {risk_score}")
        logger.info("Location Status:")
        logger.info(f"- Country: {country} ({'trusted' if is_trusted_country else 'untrusted'})")
        logger.info(f"- Region: {region} ({'trusted' if is_trusted_region else 'untrusted'})")
        logger.info(f"- City: {city} ({'trusted' if is_trusted_city else 'untrusted'})")

        return {
            'base_ml_risk_score': base_risk_score,
            'device_change_risk': device_change_risk,
            'location_trust_factor': location_trust,
            'failed_attempts_factor': failed_attempts_factor,
            'risk_score': risk_score
        }

    except Exception as e:
        logger.error(f"Error in risk assessment: {e}")
        return {
            'base_ml_risk_score': 'N/A',
            'device_change_risk': 'N/A',
            'location_trust_factor': 'N/A',
            'failed_attempts_factor': 'N/A',
            'risk_score': 0.5
        }


def prepare_and_train_model():
    global model, encoder_ip, encoder_agent, encoder_country, encoder_region, encoder_city, model_features

    # Fetch login attempts
    attempts = LoginAttempt.query.all()
    data = []

    # Add common user agents to ensure they're in the encoder
    common_user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
        'Mozilla/5.0 (Linux; Android 10; SM-G981B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.162 Mobile Safari/537.36',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1'
    ]

    # Create initial data with common user agents
    for user_agent in common_user_agents:
        base_data = {
            'user_id': 1,
            'ip_address': '127.0.0.1',
            'user_agent': user_agent,
            'hour': 9,
            'day_of_week': 1,
            'is_typical_hour': 1,
            'country': 'Unknown',
            'region': 'Unknown',
            'city': 'Unknown',
            'failed_attempts': 0,
            'attempts_24h': 1,
            'failed_attempts_24h': 0,
            'unique_ips_24h': 1,
            'unique_locations_24h': 1,
            'is_trusted_country': 0,
            'is_trusted_region': 0,
            'is_trusted_city': 0,
            'time_anomaly': 0,
            'label': 0
        }
        data.append(base_data)

    # Add real login attempts
    for attempt in attempts:
        user = User.query.filter_by(id=attempt.user_id).first()
        if not user:
            continue

        # Enhanced feature engineering
        login_datetime = attempt.login_time

        # Get user's typical hours
        typical_hours = get_user_typical_hours(user.id)
        is_typical_hour = 1 if login_datetime.hour in typical_hours else 0

        # Calculate velocity features
        time_window = login_datetime - datetime.timedelta(hours=24)
        recent_attempts = LoginAttempt.query.filter(
            LoginAttempt.user_id == user.id,
            LoginAttempt.login_time >= time_window
        ).all()

        velocity_features = {
            'attempts_24h': len(recent_attempts),
            'failed_attempts_24h': sum(1 for a in recent_attempts if a.label == 1),
            'unique_ips_24h': len(set(a.ip_address for a in recent_attempts)),
            'unique_locations_24h': len(set((a.country, a.region, a.city) for a in recent_attempts))
        }

        # Location risk features
        trusted_locations = TrustedLocation.query.filter_by(user_id=user.id).all()
        location_features = {
            'is_trusted_country': 1 if any(tl.country == attempt.country for tl in trusted_locations) else 0,
            'is_trusted_region': 1 if any(tl.region == attempt.region for tl in trusted_locations) else 0,
            'is_trusted_city': 1 if any(tl.city == attempt.city for tl in trusted_locations) else 0,
        }

        attempt_data = {
            'user_id': attempt.user_id,
            'ip_address': attempt.ip_address,
            'user_agent': attempt.user_agent,
            'hour': login_datetime.hour,
            'day_of_week': login_datetime.weekday(),
            'is_typical_hour': is_typical_hour,
            'country': attempt.country if attempt.country else 'Unknown',
            'region': attempt.region if attempt.region else 'Unknown',
            'city': attempt.city if attempt.city else 'Unknown',
            'failed_attempts': user.failed_attempts,
            **velocity_features,
            **location_features,
            'time_anomaly': 1 - is_typical_hour,
            'label': attempt.label
        }
        data.append(attempt_data)

    # Add synthetic data
    synthetic_data = generate_synthetic_attempts(1000)
    data.extend(synthetic_data)

    # Convert to DataFrame
    df = pd.DataFrame(data)

    # Enhanced feature encoding
    categorical_features = ['ip_address', 'user_agent', 'country', 'region', 'city']
    for feature in categorical_features:
        encoder = LabelEncoder()
        df[f'{feature}_encoded'] = encoder.fit_transform(df[feature])
        globals()[f'encoder_{feature.split("_")[0]}'] = encoder

    # Define features first
    features = [
        # Primary behavioral features
        'failed_attempts',          # Current failed attempts
        'failed_attempts_24h',      # Failed attempts in last 24h
        'attempts_24h',             # Total attempts in last 24h
        'unique_ips_24h',          # Number of different IPs used
        'unique_locations_24h',     # Location changes
        'is_typical_hour',         # User's normal login time
        'time_anomaly',            # Unusual timing
        
        # Secondary features (with less weight)
        'hour',
        'day_of_week',
        'ip_address_encoded',
        'user_agent_encoded',
        'country_encoded',
        'region_encoded',
        'city_encoded',
        'is_trusted_country',
        'is_trusted_region',
        'is_trusted_city'
    ]

    # Assign to global model_features
    model_features = features

    # Modify GradientBoostingClassifier parameters to adjust feature importance
    model = GradientBoostingClassifier(
        n_estimators=100,
        random_state=42,
        learning_rate=0.1,
        max_depth=5,  # Limit tree depth to prevent overfitting on location features
        subsample=0.8  # Use random subsets of the data
    )

    X = df[features]
    y = df['label']

    # Apply SMOTE with adjusted k_neighbors
    smote = SMOTE(random_state=42, k_neighbors=1)
    X_balanced, y_balanced = smote.fit_resample(X, y)

    # Verify new label distribution
    balanced_label_counts = pd.Series(y_balanced).value_counts()
    print("\nLabel Distribution After SMOTE:")
    print(balanced_label_counts)

    # Modify feature weights through sample weights
    sample_weights = np.ones(len(X_balanced))
    
    # Identify indices for different feature types
    device_change_indices = y_balanced[
        (X_balanced['user_agent_encoded'] != X_balanced['user_agent_encoded'].mode()[0])
    ].index
    location_indices = y_balanced[
        (X_balanced['is_trusted_country'] == 1) & 
        (X_balanced['is_trusted_region'] == 1) & 
        (X_balanced['is_trusted_city'] == 1)
    ].index
    
    # Adjust weights
    sample_weights[device_change_indices] *= 2.0  # Increase importance of device changes
    sample_weights[location_indices] *= 1.5  # Keep location importance
    
    # Modified GradientBoostingClassifier parameters
    model = GradientBoostingClassifier(
        n_estimators=150,
        random_state=42,
        learning_rate=0.08,
        max_depth=4,
        subsample=0.8,
        max_features='sqrt'
    )

    # Train with sample weights
    model.fit(X_balanced, y_balanced, sample_weight=sample_weights)

    # Print feature importance once
    feature_importance = pd.DataFrame({
        'feature': features,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    print("\nFeature Importance:")
    print(feature_importance)

    # Save the model and encoders
    joblib.dump(model, 'model.joblib')
    joblib.dump({
        'encoder_ip': encoder_ip,
        'encoder_agent': encoder_agent,
        'encoder_country': encoder_country,
        'encoder_region': encoder_region,
        'encoder_city': encoder_city,
        'model_features': features  # Use features directly here
    }, 'encoders.joblib')

def init_model():
    """Initialize the model once at startup"""
    global model, encoder_ip, encoder_agent, encoder_country, encoder_region, encoder_city, model_features
    
    with app.app_context():
        db.create_all()
        
        # Common default values
        common_user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (Linux; Android 10; SM-G981B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.162 Mobile Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1'
        ]
        
        # Initialize and fit encoders with default values
        encoder_ip = LabelEncoder().fit(['127.0.0.1', '192.168.1.1'])
        encoder_agent = LabelEncoder().fit(common_user_agents)
        encoder_country = LabelEncoder().fit(['Unknown', 'Taiwan', 'Japan', 'Singapore', 'United States'])
        encoder_region = LabelEncoder().fit(['Unknown', 'Taipei', 'Tokyo', 'Singapore', 'California'])
        encoder_city = LabelEncoder().fit(['Unknown', 'Taipei', 'Tokyo', 'Singapore', 'Mountain View'])
        
        # Try to load existing model and encoders
        try:
            model = joblib.load('model.joblib')
            encoders = joblib.load('encoders.joblib')
            
            # Update encoders with saved values while preserving default values
            encoder_ip = LabelEncoder().fit(list(set(list(encoder_ip.classes_) + list(encoders['encoder_ip'].classes_))))
            encoder_agent = LabelEncoder().fit(list(set(list(encoder_agent.classes_) + list(encoders['encoder_agent'].classes_))))
            encoder_country = LabelEncoder().fit(list(set(list(encoder_country.classes_) + list(encoders['encoder_country'].classes_))))
            encoder_region = LabelEncoder().fit(list(set(list(encoder_region.classes_) + list(encoders['encoder_region'].classes_))))
            encoder_city = LabelEncoder().fit(list(set(list(encoder_city.classes_) + list(encoders['encoder_city'].classes_))))
            
            model_features = encoders['model_features']
            logger.info("Loaded existing model and merged encoder classes")
        except Exception as e:
            logger.info(f"Training new model... ({str(e)})")
            prepare_and_train_model()
        
        schedule_model_retraining()

def generate_synthetic_attempts(num_samples):
    synthetic_data = []
    common_user_agents = [
        'default_device',  # Our baseline device
        'new_device',      # Our test device
        'unknown_device'   # Represent potentially suspicious devices
    ]
    
    for _ in range(num_samples):
        # Base pattern: users typically stick to 1-2 devices
        user_devices = random.sample(common_user_agents, k=random.choices([1, 2, 3], weights=[0.6, 0.3, 0.1])[0])
        current_device = random.choice(user_devices)
        
        # Time-based patterns
        hour = random.randint(0, 23)
        is_typical_hour = random.choices([1, 0], weights=[0.8, 0.2])[0]
        
        # Location patterns
        is_trusted_location = random.choices([1, 0], weights=[0.8, 0.2])[0]
        
        # Calculate various metrics
        failed_attempts = random.randint(0, 5)
        failed_attempts_24h = random.randint(failed_attempts, failed_attempts + 3)
        unique_ips_24h = random.randint(1, 4)
        unique_locations_24h = random.randint(1, 3)
        
        # Determine risk based on combined factors
        is_anomalous = 0
        if any([
            failed_attempts >= 3,
            failed_attempts_24h >= 5,
            unique_ips_24h >= 3,
            unique_locations_24h >= 3,
            (not is_typical_hour and random.random() < 0.7),
            (current_device == 'unknown_device' and random.random() < 0.8),  # High chance of anomaly for unknown devices
            (len(user_devices) == 3 and random.random() < 0.6)  # Suspicious when using too many devices
        ]):
            is_anomalous = 1
        
        # Generate sample
        sample = {
            'user_id': 1,
            'ip_address': f'192.168.1.{random.randint(1, 255)}',
            'user_agent': current_device,
            'hour': hour,
            'day_of_week': random.randint(0, 6),
            'is_typical_hour': is_typical_hour,
            'country': 'Taiwan' if is_trusted_location else random.choice(['Japan', 'Singapore', 'Unknown']),
            'region': 'Taipei' if is_trusted_location else 'Unknown',
            'city': 'Taipei' if is_trusted_location else 'Unknown',
            'failed_attempts': failed_attempts,
            'attempts_24h': random.randint(max(failed_attempts_24h, 1), failed_attempts_24h + 10),
            'failed_attempts_24h': failed_attempts_24h,
            'unique_ips_24h': unique_ips_24h,
            'unique_locations_24h': unique_locations_24h,
            'is_trusted_country': is_trusted_location,
            'is_trusted_region': is_trusted_location,
            'is_trusted_city': is_trusted_location,
            'time_anomaly': 1 - is_typical_hour,
            'label': is_anomalous
        }
        synthetic_data.append(sample)
    
    return synthetic_data

def schedule_model_retraining():
    scheduler = BackgroundScheduler()
    scheduler.add_job(func=prepare_and_train_model, trigger="interval", hours=1)
    scheduler.start()

# Add a new route for testing different locations
@app.route('/test_location', methods=['POST'])
def set_test_location():
    data = request.get_json()
    session['test_ip'] = data.get('ip', '1.1.1.1')
    session['test_location'] = {
        'country': data.get('country', 'Test Country'),
        'region': data.get('region', 'Test Region'),
        'city': data.get('city', 'Test City')
    }
    return {'status': 'success'}

@app.route('/check_records')
def check_records():
    """Debug endpoint to check recorded login attempts"""
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
        # Get current time
        current_time = datetime.datetime.now()
        
        # Update all login times to current time
        LoginAttempt.query.update({LoginAttempt.login_time: current_time})
        db.session.commit()
        return 'Login times reset to current time'
    except Exception as e:
        db.session.rollback()
        return f'Error resetting login times: {str(e)}'

def add_to_trusted_devices(user_id, user_agent):
    """Add device to trusted devices after successful verification"""
    # Only add trusted devices if not in test mode
    is_test = session.get('is_test_mode', False)
    
    if not is_test and user_agent:
        existing_device = TrustedDevice.query.filter_by(
            user_id=user_id,
            user_agent=user_agent
        ).first()

        if not existing_device:
            logger.info(f"Adding new trusted device for user {user_id}")
            new_device = TrustedDevice(
                user_id=user_id,
                user_agent=user_agent
            )
            db.session.add(new_device)
            db.session.commit()
            logger.info("Device added successfully")

if __name__ == '__main__':
    init_model()
    app.run(debug=True, host='0.0.0.0', port=5000)
