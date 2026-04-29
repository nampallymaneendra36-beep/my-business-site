from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import db


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    email = db.Column(db.String(120), unique=True)
    password_hash = db.Column(db.String(200))

    is_admin = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(20), default="user")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def has_role(self, *roles):
        return self.role in roles or self.is_admin


class ContactMessage(db.Model):
    __tablename__ = "contact_messages"

    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.String(100))
    email = db.Column(db.String(120))
    subject = db.Column(db.String(200))
    message = db.Column(db.Text)

    status = db.Column(db.String(50), default="New")
    is_read = db.Column(db.Boolean, default=False)

    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer)

    ai_priority = db.Column(db.String(50))
    ai_category = db.Column(db.String(100))
    ai_action = db.Column(db.String(200))


class SecurityEvent(db.Model):
    __tablename__ = "security_events"

    id = db.Column(db.Integer, primary_key=True)

    ip_address = db.Column(db.String(100))
    path = db.Column(db.String(300))
    method = db.Column(db.String(20))
    attack_type = db.Column(db.String(100))
    payload = db.Column(db.Text)

    country = db.Column(db.String(120), default="Unknown")
    city = db.Column(db.String(120), default="")
    lat = db.Column(db.Float, default=20.5937)
    lon = db.Column(db.Float, default=78.9629)
    source_type = db.Column(db.String(50), default="External")

    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class BlockedIP(db.Model):
    __tablename__ = "blocked_ips"

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(100), unique=True)
    blocked_at = db.Column(db.DateTime, default=datetime.utcnow)


class LoginAudit(db.Model):
    __tablename__ = "login_audit"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer)
    email = db.Column(db.String(120))

    ip_address = db.Column(db.String(100))
    user_agent = db.Column(db.Text)

    status = db.Column(db.String(20))  # SUCCESS / FAILED / LOGOUT

    timestamp = db.Column(db.DateTime, default=datetime.utcnow)