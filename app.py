from flask import Flask, render_template, redirect, url_for, request, session, flash
from models import db, User, LoginAttempt, TrustedLocation
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
    user_id = session.get('user_id')
    if not user_id:
        return 'Session expired. Please log in again.', 401

    user = User.query.get_or_404(user_id)
    if not user:
        return 'User not found.', 404

    if request.method == 'POST':
        answer = request.form.get('security_answer')
        add_to_trusted = request.form.get('add_to_trusted', 'false').lower() == 'true'
        
        if check_password_hash(user.security_answer, answer):
            login_attempt = LoginAttempt.query.filter_by(user_id=user_id).order_by(LoginAttempt.id.desc()).first()
            if login_attempt:
                login_attempt.label = 0  # Mark as legitimate
                
                # Only add to trusted locations if explicitly requested
                if add_to_trusted:
                    if (login_attempt.country not in ['Unknown', 'None'] and 
                        login_attempt.region not in ['Unknown', 'None'] and 
                        login_attempt.city not in ['Unknown', 'None']):
                        
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
                
                db.session.commit()

            # Retrain the model with updated data
            prepare_and_train_model()

            # Log the user in
            session['user_id'] = user_id
            return redirect(url_for('dashboard'))
        else:
            flash('Incorrect answer. Please try again.')
            return render_template('security_question.html', question=user.security_question)
    else:
        return render_template('security_question.html', question=user.security_question)

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
        user = User.query.filter_by(username=username).first()

        if user:
            if not user.is_active:
                flash('Please confirm your email before logging in.')
                return render_template('login.html')

            if user.is_locked:
                flash('Your account is locked.')
                return render_template('login.html', show_unlock=True, username=username)

            if not check_password_hash(user.password, password):
                # Incorrect password
                user.failed_attempts += 1
                db.session.commit()
                print(f"Failed attempts for user {user.username}: {user.failed_attempts}")

                # Lock account after too many failed attempts
                MAX_FAILED_ATTEMPTS = 5
                if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
                    user.is_locked = True
                    db.session.commit()
                    flash('Your account has been locked due to too many failed attempts.')
                    return render_template('login.html', show_unlock=True, username=username)

                flash('Invalid credentials')
                return render_template('login.html')

            # Collect contextual data for risk assessment
            ip_address = get_client_ip()
            user_agent = request.headers.get('User-Agent')
            login_time = datetime.datetime.fromisoformat(request.form.get('simulated_time')) \
                if request.form.get('simulated_time') \
                else datetime.datetime.now()
            login_hour = login_time.hour
            login_day = login_time.weekday()
            country, region, city = get_geolocation(ip_address)

            # Add this line to define recent_attempts
            recent_attempts = LoginAttempt.query.filter_by(user_id=user.id).filter(
                LoginAttempt.login_time >= login_time - datetime.timedelta(hours=24)
            ).all()

            # Perform risk assessment before resetting failed attempts
            risk_score = assess_risk_ml(ip_address, user_agent, login_time, country, region, city, user)
            print(f"Risk score for user {user.username}: {risk_score}")
            session['risk_score'] = risk_score

            # Get trusted locations
            trusted_locations = TrustedLocation.query.filter_by(user_id=user.id).all()
            trusted_countries = set(loc.country for loc in trusted_locations)
            trusted_regions = set(loc.region for loc in trusted_locations)
            trusted_cities = set(loc.city for loc in trusted_locations)

            # Add logging for location data
            print(f"\nLogin attempt details:")
            print(f"IP: {ip_address}")
            print(f"Location: {country}, {region}, {city}")
            print(f"Previous trusted locations: {trusted_countries}")
            print(f"Previous login locations: {[f'{a.country}, {a.region}, {a.city}' for a in recent_attempts]}")

            # Store login attempt
            login_attempt = LoginAttempt(
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                login_time=login_time,
                login_hour=login_hour,
                login_day=login_day,
                country=country if country else 'Unknown',
                region=region if region else 'Unknown',
                city=city if city else 'Unknown',
                label=label_attempt(user.id, ip_address, user_agent, country, region, city)
            )
            db.session.add(login_attempt)
            db.session.commit()  # Commit immediately to ensure the attempt is recorded

            # Reset failed attempts only after risk assessment
            user.failed_attempts = 0
            db.session.commit()

            if risk_score < 0.3:
                session['user_id'] = user.id
                return redirect(url_for('dashboard'))
            elif risk_score < 0.6:
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
        # Handle the case where user_id is not in session
        flash('Session expired. Please log in again.')
        return redirect(url_for('login'))

    user = User.query.get_or_404(user_id)
    if not user:
        flash('User not found.')
        return redirect(url_for('login'))

    risk_score = session.get('risk_score', 'N/A')
    return render_template('dashboard.html', username=user.username, risk_score=risk_score)

@app.route('/verify_identity', methods=['GET', 'POST'])
def verify_identity():
    if request.method == 'POST':
        # Get the OTP code entered by the user
        entered_otp = request.form.get('otp')
        if 'otp' in session and entered_otp == session['otp']:
            # Verification successful
            user_id = session.get('user_id')
            if user_id:
                # Mark the current attempt as legitimate
                login_attempt = LoginAttempt.query.filter_by(user_id=user_id).order_by(LoginAttempt.id.desc()).first()
                if login_attempt:
                    login_attempt.label = 0  # Mark as legitimate
                    db.session.commit()

                    # Add new trusted location if not already trusted and not unknown
                    if (login_attempt.country not in ['Unknown', 'None'] and 
                        login_attempt.region not in ['Unknown', 'None'] and 
                        login_attempt.city not in ['Unknown', 'None']):
                        
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
                        
                    db.session.commit()

                # Retrain the model with updated data
                prepare_and_train_model()

                # Log the user in
                session['user_id'] = user_id
                # Remove OTP from session
                session.pop('otp', None)
                session.pop('otp_generated_at', None)
                session.pop('otp_attempts', None)

                return redirect(url_for('dashboard'))
            else:
                return 'Session expired. Please log in again.', 401
        else:
            # Verification failed
            session['otp_attempts'] = session.get('otp_attempts', 0) + 1
            if session['otp_attempts'] >= 3:
                # Too many failed attempts
                session.pop('otp', None)
                session.pop('otp_generated_at', None)
                session.pop('otp_attempts', None)
                return 'Too many failed attempts. Please log in again.', 401
            return 'Verification failed', 401
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

def assess_risk_ml(ip_address, user_agent, login_time, country, region, city, user):
    global model, encoder_ip, encoder_agent, encoder_country, encoder_region, encoder_city, model_features

    if model is None:
        # If no model exists, consider it medium risk
        return 0.5

    # Calculate recent attempts
    recent_attempts = LoginAttempt.query.filter_by(
        user_id=user.id,
    ).filter(
        LoginAttempt.login_time >= login_time - datetime.timedelta(hours=24)
    ).all()
    failed_attempts_24h = sum(1 for a in recent_attempts if a.label == 1)
    unique_ips_24h = len(set(a.ip_address for a in recent_attempts))
    unique_locations_24h = len(set((a.country, a.region, a.city) for a in recent_attempts))

    # Get user's typical hours
    typical_hours = get_user_typical_hours(user.id)
    is_typical_hour = 1 if login_time.hour in typical_hours else 0
    time_anomaly = 1 - is_typical_hour

    # Trusted locations
    trusted_countries = [tl.country for tl in user.trusted_locations]
    trusted_regions = [tl.region for tl in user.trusted_locations]
    trusted_cities = [tl.city for tl in user.trusted_locations]

    is_trusted_country = 1 if country in trusted_countries else 0
    is_trusted_region = 1 if region in trusted_regions else 0
    is_trusted_city = 1 if city in trusted_cities else 0

    # Encoding features
    def safe_encode(encoder, value):
        try:
            if value in encoder.classes_:
                return encoder.transform([value])[0]
            else:
                return -1  # Assign -1 to unseen categories
        except (ValueError, AttributeError):
            return -1

    ip_address_encoded = safe_encode(encoder_ip, ip_address)
    user_agent_encoded = safe_encode(encoder_agent, user_agent)
    country_encoded = safe_encode(encoder_country, country)
    region_encoded = safe_encode(encoder_region, region)
    city_encoded = safe_encode(encoder_city, city)

    # Prepare input data
    input_data = pd.DataFrame({
        'ip_address_encoded': [ip_address_encoded],
        'user_agent_encoded': [user_agent_encoded],
        'hour': [login_time.hour],
        'day_of_week': [login_time.weekday()],
        'is_typical_hour': [is_typical_hour],
        'country_encoded': [country_encoded],
        'region_encoded': [region_encoded],
        'city_encoded': [city_encoded],
        'failed_attempts': [user.failed_attempts],
        'attempts_24h': [len(recent_attempts)],
        'failed_attempts_24h': [failed_attempts_24h],
        'unique_ips_24h': [unique_ips_24h],
        'unique_locations_24h': [unique_locations_24h],
        'is_trusted_country': [is_trusted_country],
        'is_trusted_region': [is_trusted_region],
        'is_trusted_city': [is_trusted_city],
        'time_anomaly': [time_anomaly],
    })

    # Ensure columns match model features
    try:
        input_data = input_data[model_features]
    except KeyError as e:
        missing_features = set(model_features) - set(input_data.columns)
        logger.error(f"Missing features in input data: {missing_features}")
        return 0.5  # Default risk score on error

    # Log the features used for the prediction
    logger.info(f"Risk assessment input data:\n{input_data}")
    logger.info(f"Failed attempts for user {user.username}: {user.failed_attempts}")

    # Add direct location risk factor
    location_risk = 0.0
    if country not in trusted_countries:
        location_risk += 0.3
    if region not in trusted_regions:
        location_risk += 0.2
    if city not in trusted_cities:
        location_risk += 0.1

    # Make prediction
    try:
        risk_probs = model.predict_proba(input_data)[0]
        anomalous_index = list(model.classes_).index(1)
        risk_score = risk_probs[anomalous_index]
        
        # Combine ML risk with location risk
        risk_score = max(risk_score, location_risk)

        # Adjust risk score based on failed attempts
        if user.failed_attempts >= 3:
            risk_score = max(0.4, risk_score)  # Ensure at least OTP verification
        
        # Cap the risk score at 0.6 for location-based risks
        if location_risk > 0.5:
            risk_score = min(max(0.6, risk_score), 1.0)

    except Exception as e:
        logger.error(f"Error in risk assessment: {e}")
        risk_score = 0.5

    # Add logging for risk factors
    print(f"\nRisk Assessment Details:")
    print(f"Base ML Risk Score: {risk_probs[anomalous_index]}")
    print(f"Location Risk: {location_risk}")
    print(f"Final Risk Score: {risk_score}")
    print(f"Location Status:")
    print(f"- Country: {country} ({'trusted' if country in trusted_countries else 'untrusted'})")
    print(f"- Region: {region} ({'trusted' if region in trusted_regions else 'untrusted'})")
    print(f"- City: {city} ({'trusted' if city in trusted_cities else 'untrusted'})")

    return risk_score

def prepare_and_train_model():
    global model, encoder_ip, encoder_agent, encoder_country, encoder_region, encoder_city, model_features

    # Fetch login attempts
    attempts = LoginAttempt.query.all()
    data = []

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

    # Generate synthetic data
    synthetic_data = generate_synthetic_attempts(1000)
    data.extend(synthetic_data)

    # Convert to DataFrame
    df = pd.DataFrame(data)

    # Check label distribution
    label_counts = df['label'].value_counts()
    print("\nLabel Distribution in Training Data:")
    print(label_counts)

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

    # Train the model
    model.fit(X_balanced, y_balanced)

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
        
        # Try to load existing model
        try:
            model = joblib.load('model.joblib')
            encoders = joblib.load('encoders.joblib')
            encoder_ip = encoders['encoder_ip']
            encoder_agent = encoders['encoder_agent']
            encoder_country = encoders['encoder_country']
            encoder_region = encoders['encoder_region']
            encoder_city = encoders['encoder_city']
            model_features = encoders['model_features']
            logger.info("Loaded existing model")
        except:
            logger.info("Training new model...")
            prepare_and_train_model()
        
        schedule_model_retraining()

def generate_synthetic_attempts(num_samples):
    synthetic_data = []
    
    for _ in range(num_samples):
        # Generate core behavioral metrics
        failed_attempts = random.randint(0, 5)
        attempts_24h = random.randint(max(failed_attempts, 1), 10)
        failed_attempts_24h = failed_attempts + random.randint(0, 2)
        
        # Time-based patterns
        hour = random.randint(0, 23)
        is_typical_hour = random.choices([1, 0], weights=[0.8, 0.2])[0]  # Most logins during typical hours
        time_anomaly = 1 - is_typical_hour
        
        # Velocity checks
        unique_ips_24h = random.randint(1, 3)
        unique_locations_24h = random.randint(1, 3)
        
        # Determine risk based primarily on behavior
        is_anomalous = 0
        if any([
            failed_attempts >= 3,                    # Multiple failed attempts
            failed_attempts_24h >= 5,                # Many failures in 24h
            unique_ips_24h >= 3,                     # Multiple IPs
            unique_locations_24h >= 3,               # Multiple locations
            (not is_typical_hour and random.random() < 0.7)  # Unusual time
        ]):
            is_anomalous = 1
        
        attempt = {
            'user_id': random.randint(1, 100),
            'ip_address': f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}",
            'user_agent': random.choice(['common_browser', 'unusual_agent', 'bot_agent']),
            'hour': hour,
            'day_of_week': random.randint(0, 6),
            'is_typical_hour': is_typical_hour,
            'country': f"Country_{random.randint(1,50)}",
            'region': f"Region_{random.randint(1,20)}",
            'city': f"City_{random.randint(1,100)}",
            'failed_attempts': failed_attempts,
            'attempts_24h': attempts_24h,
            'failed_attempts_24h': failed_attempts_24h,
            'unique_ips_24h': unique_ips_24h,
            'unique_locations_24h': unique_locations_24h,
            'is_trusted_country': random.choice([0, 1]),
            'is_trusted_region': random.choice([0, 1]),
            'is_trusted_city': random.choice([0, 1]),
            'time_anomaly': time_anomaly,
            'label': is_anomalous
        }
        synthetic_data.append(attempt)
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

if __name__ == '__main__':
    if os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
        # Only initialize when the reloader is active
        init_model()
    app.run(debug=True, host='0.0.0.0', port=5000)
