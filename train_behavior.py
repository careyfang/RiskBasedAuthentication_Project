import requests
import time
from datetime import datetime, timedelta
import random
import pandas as pd
from models import LoginAttempt
from app import calculate_travel_risk
import logging

# Setup logger
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

class BehaviorTester:
    def __init__(self):
        self.session = requests.Session()
        self.base_url = 'http://localhost:5000'
        self.username = 'careyfang'
        self.password = '1234'
        self.security_answer = 'auth'
        
        # Simulated time tracking
        self.current_time = datetime.now().replace(hour=9, minute=0, second=0, microsecond=0)  # Start at 9 AM
        
        # Normal behavior patterns
        self.usual_times = [9, 10, 11, 14, 15, 16]  # Office hours
        self.usual_location = {
            'ip': '192.168.1.1',
            'country': 'Taiwan',
            'region': 'Taipei',
            'city': 'Taipei'
        }
        
        # User agents
        self.user_agents = {
            'default_device': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'new_device': 'Mozilla/5.0 (Linux; Android 10; SM-G981B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.162 Mobile Safari/537.36'
        }
        self.current_device = 'default_device'  # Start with default device

    # =======================
    # Helper Methods
    # =======================
    
    def set_location(self, location_data):
        """Set the login location by sending a POST request."""
        response = self.session.post(
            f'{self.base_url}/test_location',
            json=location_data
        )
        logger.info(f"Setting location: {location_data['country']}, {location_data['city']}")
        return response
    
    def set_time(self, hour, minute=0):
        """Set the simulated login time."""
        self.current_time = self.current_time.replace(hour=hour, minute=minute)
        logger.info(f"Simulated time set to: {self.current_time.strftime('%Y-%m-%d %H:%M')}")
        return self.current_time
    
    def advance_day(self):
        """Advance to the next day at 9 AM."""
        self.current_time += timedelta(days=1)
        self.current_time = self.current_time.replace(hour=9, minute=0)
        logger.info(f"Advancing to next day: {self.current_time.strftime('%Y-%m-%d %H:%M')}")
    
    def set_user_agent(self, device_type):
        """Change the user agent to simulate different devices."""
        if device_type in self.user_agents:
            self.current_device = device_type
            logger.info(f"User agent set to: {device_type}")
        else:
            logger.warning(f"Unknown device type: {device_type}")
    
    def login(self):
        """Perform a login attempt with the current settings."""
        # Store last login time without modifying current_time
        self.last_login_time = self.current_time
        
        # Prepare login data with simulated time
        login_data = {
            'username': self.username,
            'password': self.password,
            'simulated_time': self.current_time.isoformat(),
            'user_agent': self.user_agents[self.current_device]  # Add user agent to form data
        }
        
        # Set user agent in headers
        headers = {
            'User-Agent': self.user_agents[self.current_device]
        }
        
        response = self.session.post(
            f'{self.base_url}/login',
            data=login_data,
            headers=headers
        )
        logger.info(f"Login at {self.current_time.strftime('%Y-%m-%d %H:%M')} with device: {self.current_device}")
        logger.info(f"Response URL: {response.url}")
    
        # Handle security question if prompted
        if '/security_question' in response.url:
            self.handle_security_question(add_to_trusted=False)
        
        # Handle OTP if prompted
        elif '/verify_identity' in response.url:
            self.handle_otp_verification()
    
        return response
    
    def handle_security_question(self, add_to_trusted=True):
        """Prompt user to answer security question."""
        logger.info("Security question triggered.")
        security_answer = input("Enter security answer: ")
        response = self.session.post(
            f'{self.base_url}/security_question',
            data={
                'security_answer': security_answer,
                'add_to_trusted': add_to_trusted
            }
        )
        logger.info("Answered security question.")
        return response
    
    def handle_otp_verification(self):
        """Prompt user to enter OTP code."""
        logger.info("OTP verification required.")
        otp = input("Enter OTP code received via email/SMS: ")
        response = self.session.post(
            f'{self.base_url}/verify_identity',
            data={'otp': otp}
        )
        logger.info("OTP verification completed.")
        return response
    
    def check_records(self):
        """Retrieve and display recent login attempts and trusted locations."""
        response = self.session.get(f'{self.base_url}/check_records')
        data = response.text.split('<br>')
        
        # Print only the last 10 login attempts
        logger.info("\nRecent Login Attempts:")
        login_attempts = [x for x in data if "Time:" in x][-10:]
        for attempt in login_attempts:
            logger.info(attempt.split("Time: ")[1])
        
        # Print trusted locations
        logger.info("\nTrusted Locations:")
        trusted = [x for x in data if "Location:" in x and "Time:" not in x]
        for location in trusted:
            logger.info(location.split("Location: ")[1])
        return response

    # =======================
    # Training Phase
    # =======================
    
    def train_normal_behavior(self):
        """Simulate normal login behavior over several days to train the ML model."""
        logger.info("\n=== Training Normal Behavior ===")
        
        for day in range(5):
            logger.info(f"\nDay {day + 1}:")
            # Morning login
            morning_hour = random.choice(self.usual_times[:3])
            self.set_time(morning_hour)
            logger.info(f"Morning login at {self.current_time.strftime('%H:%M')}")
            self.set_location(self.usual_location)
            self.login()
            time.sleep(1)  # Simulate time delay
            
            # Afternoon login
            afternoon_hour = random.choice(self.usual_times[3:])
            self.set_time(afternoon_hour)
            logger.info(f"Afternoon login at {self.current_time.strftime('%H:%M')}")
            self.set_location(self.usual_location)
            self.login()
            time.sleep(1)  # Simulate time delay
            
            # Advance to next day
            self.advance_day()

    # =======================
    # Testing Phase: Specific Test Cases
    # =======================
    
    # Test Case 1: Default device + Unseen city within the same region
    def test_default_device_unseen_city(self):
        logger.info("\n=== Test Case 1: Default Device + Unseen City ===")
        unseen_city_location = {
            'ip': '203.0.113.1',  # Example IP for testing
            'country': 'Taiwan',
            'region': 'Taipei',    # Same region as usual location
            'city': 'Xindian'       # Unseen city within 'Taipei' region
        }
        self.set_time(random.choice(self.usual_times))
        self.set_location(unseen_city_location)
        self.set_user_agent('default_device')
        self.login()
        time.sleep(1)
        # Advance time to ensure Test Case 2 starts after Test Case 1
        self.advance_day()
    
    # Test Case 2: New device + Unseen city within the same region
    def test_new_device_unseen_city(self):
        logger.info("\n=== Test Case 2: New Device + Unseen City ===")
        unseen_city_location = {
            'ip': '203.0.113.2',
            'country': 'Taiwan',
            'region': 'Taipei',    # Same region as usual location
            'city': 'Yilan'       # Unseen city within 'Taipei' region
        }
        self.set_time(random.choice(self.usual_times))
        self.set_location(unseen_city_location)
        self.set_user_agent('new_device')
        self.login()
        time.sleep(1)
        # Advance time to ensure Test Case 3 starts after Test Case 2
        self.advance_day()
    
    # Test Case 3: Business trip for 3 days then return home
    def test_business_trip_then_return_home(self):
        logger.info("\n=== Test Case 3: Business Trip for 3 Days Then Return Home ===")
        business_trip_location = {
            'ip': '203.0.113.3',
            'country': 'Japan',
            'region': 'Tokyo',
            'city': 'Tokyo'
        }
        
        # Simulate 3 days in Tokyo
        for day in range(3):
            logger.info(f"\nBusiness Trip Day {day + 1}:")
            # Morning login
            morning_hour = random.choice(self.usual_times[:3])
            self.set_time(morning_hour)
            self.set_location(business_trip_location)
            self.set_user_agent('default_device')
            self.login()
            time.sleep(1)
            
            # Afternoon login
            afternoon_hour = random.choice(self.usual_times[3:])
            self.set_time(afternoon_hour)
            self.set_location(business_trip_location)
            self.set_user_agent('default_device')
            self.login()
            time.sleep(1)
            
            # Advance to next day
            self.advance_day()
        
        # Return home
        logger.info("\nReturning Home:")
        self.set_time(random.choice(self.usual_times))
        self.set_location(self.usual_location)
        self.set_user_agent('default_device')
        self.login()
        time.sleep(1)
        # Advance day after returning home
        self.advance_day()
    
    # Test Case 4: Change country
    def test_change_country(self):
        logger.info("\n=== Test Case 4: Change Country ===")
        new_country_location = {
            'ip': '198.51.100.1',
            'country': 'Singapore',
            'region': 'Singapore',
            'city': 'Singapore'
        }
        self.set_time(random.choice(self.usual_times))
        self.set_location(new_country_location)
        self.set_user_agent('default_device')
        self.login()
        time.sleep(1)
        # Advance day to ensure subsequent tests start after this
        self.advance_day()
    
    # Test Case 5: 3 Failed Attempts Before Entering Correct Password
    def test_three_failed_attempts_before_success(self):
        logger.info("\n=== Test Case 5: 3 Failed Attempts Before Correct Password ===")
        self.set_time(random.choice(self.usual_times))
        self.set_location(self.usual_location)
        self.set_user_agent('default_device')
        
        # Perform 3 failed login attempts
        for attempt in range(1, 4):
            logger.info(f"Failed Login Attempt {attempt}: Incorrect password")
            response = self.session.post(
                f'{self.base_url}/login',
                data={
                    'username': self.username,
                    'password': 'wrong_password',
                    'simulated_time': self.current_time.isoformat(),
                    'user_agent': self.user_agents[self.current_device]
                },
                headers={'User-Agent': self.user_agents[self.current_device]}
            )
            logger.info(f"Response URL: {response.url}")
            time.sleep(1)
        
        # Perform correct login attempt
        logger.info("Correct Login Attempt After Failed Attempts")
        self.login()
        time.sleep(1)
        # Advance day after testing failed attempts
        self.advance_day()
    
    # Test Case 6: Rapid Location Change
    def test_rapid_location_change(self):
        logger.info("\n=== Test Case 6: Rapid Location Change ===")
        
        rapid_locations = [
            {'ip': '203.0.113.4', 'country': 'Japan', 'region': 'Osaka', 'city': 'Osaka'},
            {'ip': '203.0.113.5', 'country': 'Hong Kong', 'region': 'Hong Kong', 'city': 'Hong Kong'},
            {'ip': '203.0.113.6', 'country': 'South Korea', 'region': 'Seoul', 'city': 'Seoul'},
            {'ip': '203.0.113.7', 'country': 'United States', 'region': 'California', 'city': 'San Francisco'}
        ]
        
        self.set_user_agent('default_device')
        
        for loc in rapid_locations:
            self.set_time(random.choice(self.usual_times))
            self.set_location(loc)
            self.login()
            time.sleep(1)
            # Advance time slightly to prevent exact same timestamps
            if self.current_time.hour < 23:
                self.set_time(self.current_time.hour + 1)
            else:
                self.set_time(0)
                self.advance_day()
        
        # Advance day after rapid location changes
        self.advance_day()
    
    # =======================
    # Test Execution
    # =======================
    
    def run_tests(self):
        """Run all defined test cases sequentially."""
        logger.info("\n=== Starting Test Suite ===")
        
        # Execute Test Cases in Order
        self.test_default_device_unseen_city()
        self.test_new_device_unseen_city()
        self.test_business_trip_then_return_home()
        self.test_change_country()
        self.test_three_failed_attempts_before_success()
        self.test_rapid_location_change()
        
        # Final record check
        logger.info("\n=== Final Record Check ===")
        self.check_records()
        
        logger.info("\n=== Test Suite Completed ===")

# =======================
# Main Execution
# =======================

if __name__ == "__main__":
    tester = BehaviorTester()
    
    # Step 1: Train normal behavior
    tester.train_normal_behavior()
    
    # Step 2: Run test cases
    tester.run_tests()
