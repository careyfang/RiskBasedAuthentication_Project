from flask import Flask, render_template, redirect, url_for, request, session
from models import db, User, LoginAttempt
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

# Import additional modules
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rba.db'

db.init_app(app)

# Global variables for the model and encoders
model = None
encoder_ip = None
encoder_agent = None

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get form data
        username = request.form['username']
        password = generate_password_hash(request.form['password'])

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

    input_data = [[ip_encoded, agent_encoded, login_time.hour]]
    risk_probs = model.predict_proba(input_data)[0]
    risk_score = risk_probs[1]  # Probability of anomalous class

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
            {'user_id': 1, 'ip_address': '127.0.0.1', 'user_agent': 'dummy_agent', 'login_time': 12, 'label': 0}
        ]

    # Convert to DataFrame
    df = pd.DataFrame(data)

    # Generate anomalous data
    anomalous_data = df.copy()
    anomalous_data['ip_address'] = anomalous_data['ip_address'].apply(lambda x: 'unknown_ip')
    anomalous_data['label'] = 1  # Label as anomalous

    # Combine datasets
    df_combined = pd.concat([df, anomalous_data], ignore_index=True)

    # Encode categorical variables
    encoder_ip = LabelEncoder()
    encoder_agent = LabelEncoder()

    df_combined['ip_encoded'] = encoder_ip.fit_transform(df_combined['ip_address'])
    df_combined['agent_encoded'] = encoder_agent.fit_transform(df_combined['user_agent'])

    # Features and Labels
    X = df_combined[['ip_encoded', 'agent_encoded', 'login_time']]
    y = df_combined['label']

    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

    # Train the model
    model = DecisionTreeClassifier()
    model.fit(X_train, y_train)

    # Evaluate the model
    accuracy = model.score(X_test, y_test)
    print(f"Model accuracy: {accuracy}")

with app.app_context():
    db.create_all()
    prepare_and_train_model()

if __name__ == '__main__':
    app.run(debug=True)
