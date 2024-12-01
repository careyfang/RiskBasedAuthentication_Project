from app import app, db
from models import TrustedLocation

def clear_trusted_locations():
    with app.app_context():
        TrustedLocation.query.delete()
        db.session.commit()
        print("Cleared all trusted locations")

if __name__ == "__main__":
    clear_trusted_locations()