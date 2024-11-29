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
from sklearn.model_selection import StratifiedShuffleSplit
from sklearn.ensemble import RandomForestClassifier
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from dotenv import load_dotenv

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
encoder_ip = None
encoder_agent = None
encoder_country = None
encoder_region = None
encoder_city = None

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/retrain_model')
def retrain_model():
    prepare_and_train_model()
    return 'Model retrained with new data.'

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
        return 'Email confirmed! You can now log in.'
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
        phone_number = request.form.get('phone_number')  # Optional
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
            phone_number=phone_number,
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

    user = User.query.get(user_id)
    if not user:
        return 'User not found.', 404

    if request.method == 'POST':
        answer = request.form.get('security_answer')
        if check_password_hash(user.security_answer, answer):
            # Mark the current attempt as legitimate
            login_attempt = LoginAttempt.query.filter_by(user_id=user_id).order_by(LoginAttempt.id.desc()).first()
            if login_attempt:
                login_attempt.label = 0  # Mark as legitimate
                db.session.commit()

                # Add new trusted location
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
    if request.headers.getlist("X-Forwarded-For"):
        ip = request.headers.getlist("X-Forwarded-For")[0]
    else:
        ip = request.remote_addr
    return ip

def get_geolocation(ip_address):
    try:
        response = requests.get(f'http://ip-api.com/json/{ip_address}')
        data = response.json()
        if data['status'] == 'success':
            return data['country'], data['regionName'], data['city']
        else:
            return None, None, None
    except:
        return None, None, None

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get form data
        username = request.form['username']
        password = request.form['password']

        # Fetch user from the database
        user = User.query.filter_by(username=username).first()

        if user:
            if not user.is_active:
                return 'Please confirm your email before logging in.', 401

            if not check_password_hash(user.password, password):
                # Incorrect password
                user.failed_attempts += 1
                db.session.commit()

                # Lock account after too many failed attempts
                MAX_FAILED_ATTEMPTS = 5
                if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
                    return 'Account locked due to too many failed login attempts.', 403

                return 'Invalid credentials', 401

            # Correct password
            # Reset failed attempts
            user.failed_attempts = 0
            db.session.commit()

            # Collect contextual data
            ip_address = get_client_ip()
            user_agent = request.headers.get('User-Agent')
            login_time = datetime.datetime.now()
            login_hour = login_time.hour
            login_day = login_time.weekday()  # 0 = Monday, 6 = Sunday
            country, region, city = get_geolocation(ip_address)

            # Store login attempt
            login_attempt = LoginAttempt(
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                login_time=login_time,
                login_hour=login_hour,
                login_day=login_day,
                country=country,
                region=region,
                city=city,
                label=label_attempt(user.id, ip_address, user_agent, country, region, city)
            )
            db.session.add(login_attempt)
            db.session.commit()

            # Retrain model with new data
            prepare_and_train_model()

            print(f"IP Address: {ip_address}")
            print(f"User Agent: {user_agent}")

            # Risk assessment
            risk_score = assess_risk_ml(ip_address, user_agent, login_time, country, region, city, user)
            print(f"Risk score for user {user.username}: {risk_score}")

            if risk_score < 0.5:
                # Low risk - allow login
                session['user_id'] = user.id
                return redirect(url_for('dashboard'))
            elif risk_score < 0.8:
                # Medium risk - require additional authentication
                session['user_id'] = user.id
                return redirect(url_for('verify_identity'))
            else:
                # High risk - require security question
                session['user_id'] = user.id
                return redirect(url_for('security_question'))

        else:
            # User does not exist
            return 'Invalid credentials', 401

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        risk_score = session.get('risk_score', 'N/A')
        return render_template('dashboard.html', username=user.username, risk_score=risk_score)
    else:
        return redirect(url_for('login'))

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

                    # Add new trusted location
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
        user = db.session.get(User, user_id)
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
    # Fetch login attempts for the user
    attempts = LoginAttempt.query.filter_by(user_id=user_id, label=0).all()
    if not attempts:
        return list(range(24))  # If no data, assume all hours are typical

    # Collect login hours
    hours = [attempt.login_hour for attempt in attempts]
    # Determine typical hours (e.g., hours with more than one login)
    from collections import Counter
    hour_counts = Counter(hours)
    typical_hours = [hour for hour, count in hour_counts.items() if count > 1]
    if not typical_hours:
        typical_hours = hours  # If no hour occurs more than once, consider all logged hours as typical
    return typical_hours


def label_attempt(user_id, ip_address, user_agent, country, region, city):
    previous_attempts = LoginAttempt.query.filter_by(user_id=user_id, label=0).all()
    if not previous_attempts:
        return 0  # First login attempt is considered legitimate

    # Define criteria for anomalous attempts
    previous_ips = set(a.ip_address for a in previous_attempts)
    previous_agents = set(a.user_agent for a in previous_attempts)

    # Get user's trusted locations
    trusted_locations = TrustedLocation.query.filter_by(user_id=user_id).all()
    trusted_countries = set(loc.country for loc in trusted_locations)
    trusted_regions = set(loc.region for loc in trusted_locations)
    trusted_cities = set(loc.city for loc in trusted_locations)

    # Check if current location is trusted
    if (country in trusted_countries and region in trusted_regions and city in trusted_cities):
        location_trusted = True
    else:
        location_trusted = False

    if (ip_address not in previous_ips or
        user_agent not in previous_agents or
        not location_trusted):
        return 1  # Anomalous
    else:
        return 0  # Legitimate


def assess_risk_ml(ip_address, user_agent, login_time, country, region, city, user):
    global model
    global encoder_ip
    global encoder_agent
    global encoder_country
    global encoder_region
    global encoder_city

    # Encode input data
    if ip_address in encoder_ip.classes_:
        ip_encoded = encoder_ip.transform([ip_address])[0]
    else:
        ip_encoded = -1  # Use -1 for unknown IPs

    if user_agent in encoder_agent.classes_:
        agent_encoded = encoder_agent.transform([user_agent])[0]
    else:
        agent_encoded = -1  # Use -1 for unknown agents

    if country in encoder_country.classes_:
        country_encoded = encoder_country.transform([country])[0]
    else:
        country_encoded = -1

    if region in encoder_region.classes_:
        region_encoded = encoder_region.transform([region])[0]
    else:
        region_encoded = -1

    if city in encoder_city.classes_:
        city_encoded = encoder_city.transform([city])[0]
    else:
        city_encoded = -1

    # Determine if login time is within typical hours
    typical_hours = get_user_typical_hours(user.id)
    time_anomaly = 1 if login_time.hour not in typical_hours else 0

    input_data = pd.DataFrame({
        'ip_encoded': [ip_encoded],
        'agent_encoded': [agent_encoded],
        'login_time': [login_time.hour],
        'login_day': [login_time.weekday()],
        'country_encoded': [country_encoded],
        'region_encoded': [region_encoded],
        'city_encoded': [city_encoded],
        'failed_attempts': [user.failed_attempts],
        'time_anomaly': [time_anomaly],
    })

    # Get prediction probabilities
    risk_probs = model.predict_proba(input_data)[0]
    # Get the classes from the model
    classes = model.classes_

    # Handle the case where only one class is predicted
    if len(classes) == 1:
        if classes[0] == 0:
            risk_score = 0.0  # Model predicts only legitimate
        else:
            risk_score = 1.0  # Model predicts only anomalous
    else:
        # Get the index of the anomalous class (label 1)
        anomalous_index = list(classes).index(1)
        risk_score = risk_probs[anomalous_index]

    return risk_score  # Risk score between 0 and 1

def prepare_and_train_model():
    global model
    global encoder_ip
    global encoder_agent
    global encoder_country
    global encoder_region
    global encoder_city

    # Fetch login attempts
    attempts = LoginAttempt.query.all()
    data = []

    for attempt in attempts:
        # Get user to access failed_attempts
        user = User.query.filter_by(id=attempt.user_id).first()
        if not user:
            continue

        # Determine time anomaly
        typical_hours = get_user_typical_hours(user.id)
        time_anomaly = 1 if attempt.login_hour not in typical_hours else 0

        attempt_data = {
            'user_id': attempt.user_id,
            'ip_address': attempt.ip_address,
            'user_agent': attempt.user_agent,
            'login_time': attempt.login_hour,
            'login_day': attempt.login_day,
            'country': attempt.country if attempt.country else 'Unknown',
            'region': attempt.region if attempt.region else 'Unknown',
            'city': attempt.city if attempt.city else 'Unknown',
            'failed_attempts': user.failed_attempts,
            'time_anomaly': time_anomaly,
            'label': attempt.label
        }
        data.append(attempt_data)

    # **Add this block to handle empty data**
    if not data:
        # Create dummy data for demonstration purposes
        data = [
            {
                'user_id': 1,
                'ip_address': '127.0.0.1',
                'user_agent': 'dummy_agent',
                'login_time': 12,
                'login_day': 0,
                'country': 'CountryA',
                'region': 'RegionA',
                'city': 'CityA',
                'failed_attempts': 0,
                'time_anomaly': 0,
                'label': 0
            },
            {
                'user_id': 1,
                'ip_address': 'unknown_ip',
                'user_agent': 'dummy_agent',
                'login_time': 12,
                'login_day': 0,
                'country': 'CountryB',
                'region': 'RegionB',
                'city': 'CityB',
                'failed_attempts': 3,
                'time_anomaly': 1,
                'label': 1
            }
        ]

    # Convert to DataFrame
    df = pd.DataFrame(data)

    # Ensure both classes have at least two samples
    class_counts = df['label'].value_counts().to_dict()

    for label in [0, 1]:
        if class_counts.get(label, 0) < 2:
            # Generate synthetic data to augment the class
            samples_needed = 2 - class_counts.get(label, 0)
            for _ in range(samples_needed):
                synthetic_sample = pd.DataFrame([{
                    'user_id': 1,
                    'ip_address': '127.0.0.1' if label == 0 else 'unknown_ip',
                    'user_agent': 'dummy_agent',
                    'login_time': 12,
                    'login_day': 0,
                    'country': 'CountryA' if label == 0 else 'CountryB',
                    'region': 'RegionA' if label == 0 else 'RegionB',
                    'city': 'CityA' if label == 0 else 'CityB',
                    'failed_attempts': 0 if label == 0 else 3,
                    'time_anomaly': 0 if label == 0 else 1,
                    'label': label
                }])
                df = pd.concat([df, synthetic_sample], ignore_index=True)

    # Encode categorical variables
    encoder_ip = LabelEncoder()
    encoder_agent = LabelEncoder()
    encoder_country = LabelEncoder()
    encoder_region = LabelEncoder()
    encoder_city = LabelEncoder()

    df['ip_encoded'] = encoder_ip.fit_transform(df['ip_address'])
    df['agent_encoded'] = encoder_agent.fit_transform(df['user_agent'])
    df['country_encoded'] = encoder_country.fit_transform(df['country'])
    df['region_encoded'] = encoder_region.fit_transform(df['region'])
    df['city_encoded'] = encoder_city.fit_transform(df['city'])

    # Features and Labels
    X = df[['ip_encoded', 'agent_encoded', 'login_time', 'login_day', 'country_encoded',
            'region_encoded', 'city_encoded', 'failed_attempts', 'time_anomaly']]
    y = df['label']

    n_samples = len(df)
    n_classes = y.nunique()

    # Calculate minimum test size to ensure at least one sample per class
    min_test_size = n_classes / n_samples

    # Ensure test_size is at least the minimum required and not more than 0.5
    test_size = max(min_test_size, 0.2)
    test_size = min(test_size, 0.5)

    # Adjust n_splits to 1 since the dataset is small
    sss = StratifiedShuffleSplit(n_splits=1, test_size=test_size, random_state=42)
    try:
        for train_index, test_index in sss.split(X, y):
            X_train, X_test = X.iloc[train_index], X.iloc[test_index]
            y_train, y_test = y.iloc[train_index], y.iloc[test_index]
    except ValueError as e:
        print(f"Warning: {e}")
        # If splitting fails, use the entire dataset for training and testing
        X_train, X_test = X, X
        y_train, y_test = y, y

    # Train the model
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # Evaluate the model
    if len(y_test) > 0:
        accuracy = model.score(X_test, y_test)
        print(f"Model accuracy: {accuracy}")
    else:
        print("Not enough data to evaluate model accuracy.")

# Create the database and tables
with app.app_context():
    db.create_all()
    prepare_and_train_model()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
