import requests
import time

def test_location(location_data):
    # Create a session to maintain cookies
    s = requests.Session()
    
    # Set test location
    response = s.post('http://localhost:5000/test_location', json=location_data)
    print(f"Set location response: {response.status_code}")
    
    # Attempt login
    login_data = {
        'username': 'carey',
        'password': '1234'
    }
    response = s.post('http://localhost:5000/login', data=login_data)
    
    # Check records after login
    records = s.get('http://localhost:5000/check_records')
    print("\nCurrent Records:")
    print(records.text)
    
    return response

# Test different locations
locations = [
    {
        'ip': '127.0.0.1',              # Local IP
        'country': 'Local',
        'region': 'Local',
        'city': 'Local'
    },
    {
        'ip': '203.104.248.60',         # Japan IP
        'country': 'Japan',
        'region': 'Tokyo',
        'city': 'Tokyo'
    },
    {
        'ip': '8.8.8.8',                # Different IP, same location
        'country': 'Japan',
        'region': 'Tokyo',
        'city': 'Tokyo'
    },
    {
        'ip': '1.1.1.1',                # Another different IP, same location
        'country': 'Japan',
        'region': 'Tokyo',
        'city': 'Tokyo'
    }
]

for location in locations:
    print(f"\nTesting login from {location['country']}, {location['city']}")
    response = test_location(location)
    print(f"Response status: {response.status_code}")
    print(f"Response URL: {response.url}")  # This will show where we were redirected
    time.sleep(2)  # Wait between tests