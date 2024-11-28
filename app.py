from flask import Flask, render_template, redirect, url_for, request, session
from models import db, User, LoginAttempt
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import StratifiedShuffleSplit
from sklearn.tree import DecisionTreeClassifier

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rba.db'

db.init_app(app)

# Global variables for the model and encoders
model = None
encoder_ip = None
encoder_agent = None

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/retrain_model')
def retrain_model():
    prepare_and_train_model()
    return 'Model retrained with new data.'

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get form data
        username = request.form['username']
        password = generate_password_hash(request.form['password'])

        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return 'Username already exists. Please choose another one.'

        # Save user to the database
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get form data
        username = request.form['username']
        password = request.form['password']

        # Fetch user from the database
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            # Collect contextual data
            ip_address = request.remote_addr
            user_agent = request.headers.get('User-Agent')
            login_time = datetime.datetime.now()

            # Store login attempt
            login_attempt = LoginAttempt(
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                login_time=login_time
            )
            db.session.add(login_attempt)
            db.session.commit()

            # Retrain model with new data (Optional)
            # prepare_and_train_model()

            # Risk assessment
            risk_score = assess_risk_ml(ip_address, user_agent, login_time, user)

            if risk_score < 0.5:
                # Low risk - allow login
                session['user_id'] = user.id
                return redirect(url_for('dashboard'))
            elif risk_score < 0.8:
                # Medium risk - require additional authentication
                return redirect(url_for('verify_identity'))
            else:
                # High risk - deny access
                return 'Access Denied: High Risk Detected', 403

        return 'Invalid credentials', 401

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        return render_template('dashboard.html', username=user.username)
    else:
        return redirect(url_for('login'))

@app.route('/verify_identity', methods=['GET', 'POST'])
def verify_identity():
    # Implement OTP or security questions
    return 'Additional verification required.'

def assess_risk_ml(ip_address, user_agent, login_time, user):
    global model
    global encoder_ip
    global encoder_agent

    # Encode input data
    if ip_address in encoder_ip.classes_:
        ip_encoded = encoder_ip.transform([ip_address])[0]
    else:
        ip_encoded = -1  # Use -1 for unknown IPs

    if user_agent in encoder_agent.classes_:
        agent_encoded = encoder_agent.transform([user_agent])[0]
    else:
        agent_encoded = -1  # Use -1 for unknown agents

    input_data = pd.DataFrame({
        'ip_encoded': [ip_encoded],
        'agent_encoded': [agent_encoded],
        'login_time': [login_time.hour]
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

    # Fetch login attempts
    attempts = LoginAttempt.query.all()
    data = []

    for attempt in attempts:
        data.append({
            'user_id': attempt.user_id,
            'ip_address': attempt.ip_address,
            'user_agent': attempt.user_agent,
            'login_time': attempt.login_time.hour,
            'label': 0  # Initially label all as legitimate
        })

    # If no data is available, create dummy data
    if not data:
        # Create dummy data for demonstration purposes
        data = [
            {'user_id': 1, 'ip_address': '127.0.0.1', 'user_agent': 'dummy_agent', 'login_time': 12, 'label': 0},
            {'user_id': 1, 'ip_address': 'unknown_ip', 'user_agent': 'dummy_agent', 'login_time': 12, 'label': 1}
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
                    'label': label
                }])
                df = pd.concat([df, synthetic_sample], ignore_index=True)

    # Encode categorical variables
    encoder_ip = LabelEncoder()
    encoder_agent = LabelEncoder()

    df['ip_encoded'] = encoder_ip.fit_transform(df['ip_address'])
    df['agent_encoded'] = encoder_agent.fit_transform(df['user_agent'])

    # Features and Labels
    X = df[['ip_encoded', 'agent_encoded', 'login_time']]
    y = df['label']

    n_samples = len(df)
    n_classes = y.nunique()

    # Calculate minimum test size to ensure at least one sample per class
    min_test_size = n_classes / n_samples

    # Ensure test_size is at least the minimum required and not more than 0.5
    test_size = max(min_test_size, 0.2)  # Use at least 20% if possible
    test_size = min(test_size, 0.5)  # Do not exceed 50%

    # Adjust n_splits to 1 since the dataset is small
    from sklearn.model_selection import StratifiedShuffleSplit

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
    model = DecisionTreeClassifier()
    model.fit(X_train, y_train)

    # Evaluate the model
    if len(y_test) > 0:
        accuracy = model.score(X_test, y_test)
        print(f"Model accuracy: {accuracy}")
    else:
        print("Not enough data to evaluate model accuracy.")

with app.app_context():
    db.create_all()
    prepare_and_train_model()

if __name__ == '__main__':
    app.run(debug=True)
