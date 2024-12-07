# manage.py

import os
import sys
import requests

def main():
    # Ensure the virtual environment is activated
    activate_env = os.path.expanduser("/home/careyfang/.virtualenvs/rba_env/bin/activate_this.py")
    if not os.path.exists(activate_env):
        print("Error: Virtual environment activation script not found.")
        sys.exit(1)
    with open(activate_env) as f:
        exec(f.read(), {'__file__': activate_env})

    # Set the Flask app environment variable
    os.environ['FLASK_APP'] = 'app.py'  # Replace 'app.py' if different

    # Retrieve the secret key from environment variables
    initialize_secret = os.environ.get('INITIALIZE_SECRET')
    if not initialize_secret:
        print("Error: INITIALIZE_SECRET environment variable not set.")
        sys.exit(1)

    # Define the URL for initialization
    initialize_url = 'https://careyfang.pythonanywhere.com/initialize_data'  # Replace 'careyfang'

    # Make the POST request to initialize data
    try:
        response = requests.post(
            initialize_url,
            data={'secret_key': initialize_secret}
        )
        if response.status_code == 200:
            print("Initialization successful.")
        else:
            print(f"Initialization failed: {response.json().get('message')}")
    except Exception as e:
        print(f"Error during initialization: {e}")

if __name__ == '__main__':
    main()
