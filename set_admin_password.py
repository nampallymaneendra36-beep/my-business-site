from app import app
from extensions import db
from models import User

ADMIN_EMAIL = "admin@ppcyber.com"
NEW_PASSWORD = "Sannapulahimasri@040799"


with app.app_context():
    user = User.query.filter_by(email=ADMIN_EMAIL).first()

    if not user:
        print("Admin user not found.")
    else:
        user.set_password(NEW_PASSWORD)
        db.session.commit()
        print("Admin password updated successfully.")