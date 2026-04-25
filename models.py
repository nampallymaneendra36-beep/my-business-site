from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import db


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    email = db.Column(db.String(120))
    password_hash = db.Column(db.String(200))
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class ContactMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(120))
    subject = db.Column(db.String(200))
    message = db.Column(db.Text)

    status = db.Column(db.String(50), default="New")
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer)

    # ✅ AI fields
    ai_priority = db.Column(db.String(50))
    ai_category = db.Column(db.String(100))
    ai_action = db.Column(db.String(200))

    