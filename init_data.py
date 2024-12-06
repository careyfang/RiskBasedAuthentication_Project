from app import app, db, MODEL_PATH, generate_synthetic_attempts
from app import User, LoginAttempt, TrustedLocation
from werkzeug.security import generate_password_hash
import datetime
import random
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def initialize_synthetic_data():
    with app.app_context():
        if not os.path.exists(MODEL_PATH):
            logger.info("Initializing synthetic data...")
            try:
                synthetic_data = generate_synthetic_attempts(5000)
                
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
                logger.info("Synthetic data initialization complete")
            except Exception as e:
                db.session.rollback()
                logger.error(f"Error initializing synthetic data: {e}")

if __name__ == '__main__':
    initialize_synthetic_data()