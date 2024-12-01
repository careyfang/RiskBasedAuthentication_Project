import requests
import time
from datetime import datetime, timedelta
import random
from itertools import groupby
import pandas as pd
from models import LoginAttempt
from app import calculate_travel_risk

class BehaviorTester:
    def __init__(self):
        self.session = requests.Session()
        self.base_url = 'http://localhost:5000'
        self.username = 'carey'
        self.password = '1234'
        self.security_answer = 'bibi'
        
        # Add simulated time tracking
        self.current_time = datetime.now().replace(hour=9, minute=0, second=0)  # Start at 9 AM
        
        # Normal behavior patterns
        self.usual_times = [9, 10, 11, 14, 15, 16]  # Office hours
        self.usual_location = {
            'ip': '192.168.1.1',
            'country': 'Taiwan',
            'region': 'Taipei',
            'city': 'Taipei'
        }
        
        # Simplify user agents to just two types
        self.user_agents = {
            'default_device': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'new_device': 'Mozilla/5.0 (Linux; Android 10; SM-G981B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.162 Mobile Safari/537.36'
        }
        self.usual_device = 'default_device'  # Set default device
        self.is_training = True

    def set_location(self, location_data):
        response = self.session.post(
            f'{self.base_url}/test_location',
            json=location_data
        )
        print(f"Setting location: {location_data['country']}, {location_data['city']}")
        return response

    def set_time(self, hour, minute=0):
        """Set the simulated time"""
        self.current_time = self.current_time.replace(hour=hour, minute=minute)
        return self.current_time

    def advance_day(self):
        """Advance to next day at 9 AM"""
        self.current_time += timedelta(days=1)
        self.current_time = self.current_time.replace(hour=9, minute=0)

    def login(self):
        # Store last login time without modifying current_time
        self.last_login_time = self.current_time
        
        # Prepare login data with simulated time
        login_data = {
            'username': self.username,
            'password': self.password,
            'simulated_time': self.current_time.isoformat()
        }
        
        # Set user agent if specified
        if hasattr(self, 'usual_device'):
            self.session.headers.update({'User-Agent': self.user_agents[self.usual_device]})
        
        response = self.session.post(
            f'{self.base_url}/login',
            data=login_data
        )
        print(f"Login at {self.current_time.strftime('%Y-%m-%d %H:%M')} - Response URL: {response.url}")

        # Handle security question if needed
        if 'security_question' in response.url:
            response = self.session.post(
                f'{self.base_url}/security_question',
                data={
                    'security_answer': self.security_answer,
                    'add_to_trusted': self.is_training
                }
            )
            print("Answered security question")
        
        # Handle OTP if needed
        elif 'verify_identity' in response.url:
            print("OTP verification required - manual intervention needed")
            otp = input("Enter OTP from email: ")
            response = self.session.post(
                f'{self.base_url}/verify_identity',
                data={'otp': otp}
            )

        return response

    def check_records(self):
        response = self.session.get(f'{self.base_url}/check_records')
        data = response.text.split('<br>')
        
        # Print only the last 10 login attempts
        print("\nRecent Login Attempts:")
        login_attempts = [x for x in data if "Time:" in x][-10:]
        for attempt in login_attempts:
            print(attempt.split("Time: ")[1])
        
        # Print trusted locations
        print("\nTrusted Locations:")
        trusted = [x for x in data if "Location:" in x and "Time:" not in x]
        for location in trusted:
            print(location.split("Location: ")[1])
        return response

    def train_normal_behavior(self):
        """Simulate normal login behavior over several days"""
        print("\n=== Training Normal Behavior ===")
        self.is_training = True  # Enable training mode
        
        for day in range(5):
            print(f"\nDay {day + 1}:")
            # Morning login
            morning_hour = random.choice(self.usual_times[:3])
            self.set_time(morning_hour)
            print(f"Morning login at {self.current_time.strftime('%H:%M')}")
            self.set_location(self.usual_location)
            self.login()
            time.sleep(1)

            # Afternoon login
            afternoon_hour = random.choice(self.usual_times[3:])
            self.set_time(afternoon_hour)
            print(f"Afternoon login at {self.current_time.strftime('%H:%M')}")
            self.set_location(self.usual_location)
            self.login()
            time.sleep(1)

            self.advance_day()

    def test_anomalies(self):
        """Test various anomalous behaviors"""
        self.is_training = False
        print("\n=== Testing Anomalies ===")

        # Test 1: Unusual Time Only
        print("\nTest 1: Unusual Time Only (3 AM) from Trusted Location")
        self.set_location(self.usual_location)
        self.login()
        time.sleep(1)

        # Test 2: Unusual Time + Location
        print("\nTest 2: Unusual Time + Location")
        unusual_location = {
            'ip': '8.8.8.8',
            'country': 'United States',
            'region': 'California',
            'city': 'Mountain View'
        }
        self.set_location(unusual_location)
        self.login()
        time.sleep(1)

        # Test 3: Multiple Failed Attempts from Trusted Location
        print("\nTest 3: Multiple Failed Attempts from Trusted Location")
        self.set_location(self.usual_location)
        for _ in range(3):
            self.session.post(
                f'{self.base_url}/login',
                data={'username': self.username, 'password': 'wrong_password'}
            )
            time.sleep(1)
        self.login()

        # Test 4: Multiple Failed Attempts + Unusual Location
        print("\nTest 4: Multiple Failed Attempts + Unusual Location")
        self.set_location(unusual_location)
        for _ in range(3):
            self.session.post(
                f'{self.base_url}/login',
                data={'username': self.username, 'password': 'wrong_password'}
            )
            time.sleep(1)
        self.login()

        # Test 5: Rapid Location Changes
        print("\nTest 5: Rapid Location Changes")
        locations = [
            {'ip': '1.1.1.1', 'country': 'Japan', 'region': 'Tokyo', 'city': 'Tokyo'},
            {'ip': '2.2.2.2', 'country': 'Singapore', 'region': 'Singapore', 'city': 'Singapore'},
            {'ip': '3.3.3.3', 'country': 'Hong Kong', 'region': 'Hong Kong', 'city': 'Hong Kong'}
        ]
        for location in locations:
            self.set_location(location)
            self.login()
            time.sleep(1)

    def test_business_trip(self):
        """Simulate a 3-day business trip to Tokyo"""
        print("\n=== Testing Business Trip Scenario ===")
        
        business_location = {
            'ip': '203.104.248.60',
            'country': 'Japan',
            'region': 'Tokyo',
            'city': 'Tokyo'
        }

        # Day 1: First login from Tokyo (should require verification)
        print("\nDay 1 in Tokyo:")
        print("Morning login at 9:00")
        self.set_location(business_location)
        self.login()  # This should trigger security question
        time.sleep(1)

        print("Afternoon login at 15:00")
        self.set_location(business_location)
        self.login()  # Should be easier now that location is trusted
        time.sleep(1)

        # Day 2: Regular logins from Tokyo
        print("\nDay 2 in Tokyo:")
        print("Morning login at 9:30")
        self.set_location(business_location)
        self.login()
        time.sleep(1)

        print("Afternoon login at 14:00")
        self.set_location(business_location)
        self.login()
        time.sleep(1)

        # Day 3: Last day in Tokyo
        print("\nDay 3 in Tokyo:")
        print("Morning login at 10:00")
        self.set_location(business_location)
        self.login()
        time.sleep(1)

        # Return home
        print("\nReturn to home location:")
        self.set_location(self.usual_location)
        self.login()

    def set_user_agent(self, device_key):
        """Set the user agent for the session"""
        if device_key in self.user_agents:
            self.session.headers.update({'User-Agent': self.user_agents[device_key]})
        else:
            print(f"Unknown device: {device_key}")

    def test_location_trust_levels(self):
        """Test different levels of location trust"""
        print("\n=== Testing Location Trust Levels ===")
        
        # Set test mode to prevent adding locations to trusted
        self.session.post(f'{self.base_url}/set_test_mode')  # New endpoint needed
        
        locations = {
            'unseen_city': {
                'ip': '1.1.1.1',
                'country': 'Taiwan',  # Known
                'region': 'Taipei',   # Known
                'city': 'New Taipei'  # Unseen
            },
            'unseen_region': {
                'ip': '1.1.1.2',
                'country': 'Taiwan',    # Known
                'region': 'Kaohsiung',  # Unseen
                'city': 'Kaohsiung'     # Unseen
            },
            'unseen_country': {
                'ip': '1.1.1.3',
                'country': 'Malaysia',  # Unseen
                'region': 'KL',        # Unseen
                'city': 'KL'          # Unseen
            }
        }
        
        times = {
            'typical': 14,
            'unusual': 3
        }
        
        # Make sure we're not in training mode
        self.is_training = False
        
        for time_type, hour in times.items():
            print(f"\nTesting during {time_type} hours ({hour}:00):")
            self.set_time(hour)
            
            for loc_type, location in locations.items():
                # Test with default device
                print(f"\nLogin from {loc_type} using default device")
                self.set_location(location)
                self.set_user_agent('default_device')
                response = self.login()
                
                if '/security_question' in response.url:
                    print(f"Login at {self.current_time} - Response URL: {response.url}")
                    self.answer_security_question(add_to_trusted=False)  # Explicitly don't add to trusted
                    print("Answered security question")
                else:
                    print(f"Login at {self.current_time} - Response URL: {response.url}")
                
                time.sleep(1)
                
                # Test with new device
                print(f"\nLogin from {loc_type} using new device")
                self.set_location(location)
                self.set_user_agent('new_device')
                response = self.login()
                
                if '/security_question' in response.url:
                    print(f"Login at {self.current_time} - Response URL: {response.url}")
                    self.answer_security_question(add_to_trusted=False)  # Explicitly don't add to trusted
                    print("Answered security question")
                else:
                    print(f"Login at {self.current_time} - Response URL: {response.url}")
                
                time.sleep(1)

    def answer_security_question(self, add_to_trusted=True):
        """Answer security question with option to add location to trusted"""
        response = self.session.post(
            f'{self.base_url}/security_question',
            data={
                'security_answer': self.security_answer,
                'add_to_trusted': add_to_trusted
            }
        )
        return response

    def train_initial_locations(self):
        """Train the system with initial trusted locations"""
        print("\n1. Training Initial Trusted Locations")
        
        # Set training mode
        self.is_training = True
        
        trusted_locations = [
            {'country': 'Taiwan', 'region': 'Taipei', 'city': 'Taipei'},
            # Add other initial trusted locations as needed
        ]
        
        for location in trusted_locations:
            print(f"\nTraining location: {location['city']}, {location['region']}, {location['country']}")
            self.set_location({
                'ip': '1.1.1.1',
                **location
            })
            self.set_user_agent('default_device')
            response = self.login()
            
            if '/verify_identity' in response.url:
                print("Verifying identity for trusted location")
                self.verify_identity()
            
            time.sleep(1)
        
        # Clear training mode
        self.is_training = False

    def test_business_trip_multiple_cities(self):
        """Simulate a 3-day business trip with city changes and device variations"""
        print("\n=== Testing Multi-City Business Trip ===")
        
        locations = {
            'Tokyo': {
                'ip': '203.104.248.60',
                'country': 'Japan',
                'region': 'Tokyo',
                'city': 'Tokyo'
            },
            'Osaka': {
                'ip': '203.104.248.61',
                'country': 'Japan',
                'region': 'Osaka',
                'city': 'Osaka'
            },
            'Kyoto': {
                'ip': '203.104.248.62',
                'country': 'Japan',
                'region': 'Kyoto',
                'city': 'Kyoto'
            }
        }
        
        devices = ['default_device', 'new_device']
        
        for city, location in locations.items():
            print(f"\nDay in {city}:")
            self.set_location(location)
            for device in devices:
                print(f"Login using {device}")
                self.set_user_agent(device)
                self.login()
                time.sleep(1)
            self.advance_day()
        
        # Return home
        print("\nReturn to home location (using default_device)")
        self.set_location(self.usual_location)
        self.set_user_agent('default_device')
        self.login()

    def test_time_and_location_combinations(self):
        """Test various combinations of time and location"""
        print("\n=== Testing Time and Location Combinations ===")
        self.is_training = False  # Disable training mode for testing
        
        # Test 5: Trusted location + unusual time
        print("\nTest: Trusted location + unusual time (2 AM)")
        self.set_time(2)
        self.set_location(self.usual_location)
        self.login()
        time.sleep(1)
        
        # Test 6: Untrusted location + unusual time
        print("\nTest: Untrusted location + unusual time (3 AM)")
        self.set_time(3)
        unusual_location = {
            'ip': '8.8.8.8',
            'country': 'United States',
            'region': 'California',
            'city': 'Mountain View'
        }
        self.set_location(unusual_location)
        self.login()
        time.sleep(1)

    def test_failed_attempts(self):
        """Test scenarios with failed login attempts from different devices"""
        print("\n=== Testing Failed Attempts Scenarios ===")
        
        devices = ['default_device', 'new_device']
        
        # Test from trusted location
        print("\nTesting from trusted location:")
        self.set_time(14)
        self.set_location(self.usual_location)
        
        for device in devices:
            print(f"\nAttempts using {device}")
            self.set_user_agent(device)
            for _ in range(2):
                self.session.post(
                    f'{self.base_url}/login',
                    data={'username': self.username, 'password': 'wrong_password'}
                )
                time.sleep(1)
            self.login()
            time.sleep(1)
        
        # Test from unusual location
        print("\nTesting from unusual location:")
        unusual_location = {
            'ip': '8.8.8.8',
            'country': 'United States',
            'region': 'California',
            'city': 'Mountain View'
        }
        self.set_location(unusual_location)
        
        for device in devices:
            print(f"\nAttempts using {device}")
            self.set_user_agent(device)
            for _ in range(2):
                self.session.post(
                    f'{self.base_url}/login',
                    data={'username': self.username, 'password': 'wrong_password'}
                )
                time.sleep(1)
            self.login()
            time.sleep(1)

    def test_rapid_location_changes(self):
        """Test rapid changes in login location with device changes"""
        print("\n=== Testing Rapid Location Changes ===")
        
        locations = [
            {'ip': '1.1.1.1', 'country': 'Japan', 'region': 'Tokyo', 'city': 'Tokyo'},
            {'ip': '2.2.2.2', 'country': 'Singapore', 'region': 'Singapore', 'city': 'Singapore'},
            {'ip': '3.3.3.3', 'country': 'Hong Kong', 'region': 'Hong Kong', 'city': 'Hong Kong'},
            {'ip': '4.4.4.4', 'country': 'South Korea', 'region': 'Seoul', 'city': 'Seoul'}
        ]
        
        devices = ['default_device', 'new_device']
        
        self.set_time(14)
        for location, device in zip(locations, devices):
            print(f"\nLogin from {location['country']}, {location['city']} using {device}")
            self.set_location(location)
            self.set_user_agent(device)
            self.login()
            time.sleep(1)

    def run_full_test(self):
        """Run complete behavior training and anomaly testing"""
        print("\n=== Starting Full Test Suite ===")
        
        # First, train normal behavior
        self.train_normal_behavior()  # is_training = True
        self.check_records()
        
        # Run all test cases with is_training = False
        self.test_location_trust_levels()
        
        print("\n3. Testing Business Trip Scenario")
        self.test_business_trip_multiple_cities()
        
        print("\n4. Testing Time and Location Combinations")
        self.test_time_and_location_combinations()
        
        print("\n5. Testing Failed Attempts with Different Devices")
        self.test_failed_attempts()
        
        print("\n6. Testing Rapid Location and Device Changes")
        self.test_rapid_location_changes()
        
        # Final check of records
        print("\n=== Final Record Check ===")
        self.check_records()
        
        print("\n=== Full Test Suite Completed ===")

    def prepare_training_data():
        attempts = LoginAttempt.query.order_by(LoginAttempt.login_time).all()
        data = []
        
        for user_id, user_attempts in groupby(attempts, key=lambda x: x.user_id):
            user_attempts = list(user_attempts)  # Convert iterator to list
            
            for i, attempt in enumerate(user_attempts):
                # Get previous attempt for travel risk calculation
                prev_attempt = user_attempts[i-1] if i > 0 else None
                
                if prev_attempt:
                    # Calculate time difference in hours
                    time_diff = (attempt.login_time - prev_attempt.login_time).total_seconds() / 3600
                    
                    # Calculate travel risk
                    prev_location = {
                        'city': prev_attempt.city,
                        'region': prev_attempt.region,
                        'country': prev_attempt.country
                    }
                    curr_location = {
                        'city': attempt.city,
                        'region': attempt.region,
                        'country': attempt.country
                    }
                    
                    travel_risk, _ = calculate_travel_risk(prev_location, curr_location, time_diff)
                else:
                    travel_risk = 0.0
                    time_diff = 0.0
                
                # Add time-based features
                data.append({
                    'user_id': attempt.user_id,
                    'time_since_last_login': time_diff,
                    'travel_risk': travel_risk,
                    'label': attempt.label,
                    # ... other features ...
                })
        
        return pd.DataFrame(data)

if __name__ == "__main__":
    tester = BehaviorTester()
    tester.run_full_test() 