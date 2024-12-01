import requests
import time
from datetime import datetime, timedelta
import random

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
        login_data = {
            'username': self.username,
            'password': self.password,
            'simulated_time': self.current_time.isoformat()  # Add simulated time to request
        }
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
        
        # Print only the last 5 login attempts
        print("\nRecent Login Attempts:")
        login_attempts = [x for x in data if "Time:" in x][-5:]
        for attempt in login_attempts:
            print(attempt.split("Time: ")[1])
        
        # Print trusted locations
        print("\nTrusted Locations:")
        trusted = [x for x in data if "Location:" in x and "Time:" not in x]
        for location in trusted:
            print(location.split("Location: ")[1])
        return response

    def train_normal_behavior(self, days=5):
        """Simulate normal login behavior over several days"""
        print("\n=== Training Normal Behavior ===")
        
        for day in range(days):
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

    def run_full_test(self):
        """Run complete behavior training and anomaly testing"""
        # First, train normal behavior
        self.train_normal_behavior()
        
        # Check established patterns
        self.check_records()
        
        # Test business trip scenario
        self.test_business_trip()
        
        # Then test anomalies
        self.test_anomalies()
        
        # Final check of records
        self.check_records()

if __name__ == "__main__":
    tester = BehaviorTester()
    tester.run_full_test() 