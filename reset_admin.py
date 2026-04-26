from app import app
from extensions import db
from models import User

with app.app_context():
    email = "nampallymaneendra36@gmail.com"

    user = User.query.filter_by(email=email).first()

    if user:
        user.set_password("Admin@123")
        print("🔁 User exists → password updated")
    else:
        user = User(
            username="admin",
            email=email,
            is_admin=True
        )
        user.set_password("Admin@123")
        db.session.add(user)
        print("🆕 New admin created")

    db.session.commit()
    print("✅ Done")