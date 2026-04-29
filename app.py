import re
import requests
from urllib.parse import unquote
from dotenv import load_dotenv

from flask import Flask, request, render_template, jsonify
from flask_login import LoginManager
from flask_mail import Message
from sqlalchemy import text

from config import Config
from extensions import db, mail, socketio
from models import User, SecurityEvent, BlockedIP
from security_rules import ATTACK_RULES

load_dotenv()


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    print("🚨 PPC WAF + SOC + GEOIP + SOCKETIO + RULE ENGINE ACTIVE")

    db.init_app(app)
    mail.init_app(app)
    socketio.init_app(app)

    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    def normalize(data):
        data = str(data or "")
        data = unquote(data)
        data = unquote(data)
        return data.lower()

    def get_ip():
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.remote_addr or "0.0.0.0"

    def is_private_ip(ip):
        return (
            ip.startswith("127.")
            or ip.startswith("192.168.")
            or ip.startswith("10.")
            or ip.startswith("172.")
            or ip == "::1"
            or ip == "localhost"
        )

    def get_geo(ip):
        try:
            if not ip or is_private_ip(ip):
                return {
                    "country": "Localhost",
                    "city": "Internal",
                    "lat": 17.3850,
                    "lon": 78.4867,
                    "source_type": "Internal"
                }

            res = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()

            if res.get("status") == "fail":
                return {
                    "country": "Unknown",
                    "city": "",
                    "lat": 20.5937,
                    "lon": 78.9629,
                    "source_type": "External"
                }

            return {
                "country": res.get("country", "Unknown"),
                "city": res.get("city", ""),
                "lat": float(res.get("lat", 20.5937)),
                "lon": float(res.get("lon", 78.9629)),
                "source_type": "External"
            }

        except Exception as e:
            print("GEOIP ERROR:", e)
            return {
                "country": "Unknown",
                "city": "",
                "lat": 20.5937,
                "lon": 78.9629,
                "source_type": "External"
            }

    def analyze_threat(payload, attack):
        payload = str(payload or "").lower()
        attack = str(attack or "").lower()

        if attack == "xss" or "javascript" in payload or "<script" in payload:
            return "Critical", 90, "Cross-Site Scripting (XSS)", "Block IP, sanitize input"

        if attack == "sqli" or "union" in payload or "or 1=1" in payload:
            return "Critical", 85, "SQL Injection", "Block IP, review database queries"

        if attack == "command injection" or "cmd=" in payload or "powershell" in payload:
            return "High", 80, "Command Injection", "Block IP, check server command paths"

        if attack == "path traversal" or "../" in payload or "..\\" in payload:
            return "High", 70, "Path Traversal", "Validate file path handling"

        if attack in ["ssrf", "file inclusion", "sensitive file access"]:
            return "High", 75, attack, "Block request and review endpoint"

        if attack in ["scanner / recon", "malicious upload"]:
            return "Medium", 60, attack, "Monitor source and block if repeated"

        return "Medium", 40, "Suspicious Activity", "Monitor logs"

    def serialize_event(event):
        severity, score, category, action = analyze_threat(event.payload, event.attack_type)

        return {
            "id": event.id,
            "time": event.timestamp.strftime("%Y-%m-%d %H:%M:%S") if event.timestamp else "",
            "ip": event.ip_address,
            "attack": event.attack_type,
            "path": event.path,
            "method": event.method,
            "payload": event.payload,
            "severity": severity,
            "score": score,
            "category": category,
            "action": action,
            "country": event.country or "Unknown",
            "city": event.city or "",
            "lat": event.lat or 20.5937,
            "lon": event.lon or 78.9629,
            "source_type": event.source_type or "External",
            "geo_label": f"{event.country or 'Unknown'} {event.city or ''}".strip()
        }

    def send_alert(ip, attack, payload):
        try:
            msg = Message(
                subject=f"🚨 Attack Detected: {attack}",
                sender=app.config.get("MAIL_USERNAME"),
                recipients=[app.config.get("MAIL_USERNAME")],
                body=f"IP: {ip}\nAttack: {attack}\nPayload:\n{payload}"
            )
            mail.send(msg)
        except Exception as e:
            print("EMAIL ERROR:", e)

    def emit_security_event(event):
        try:
            socketio.emit("new_security_event", serialize_event(event))
        except Exception as e:
            print("SOCKET EMIT ERROR:", e)

    def log_event(ip, attack, payload):
        try:
            geo = get_geo(ip)

            event = SecurityEvent(
                ip_address=ip,
                path=request.path,
                method=request.method,
                attack_type=attack,
                payload=payload[:1000],
                country=geo["country"],
                city=geo["city"],
                lat=geo["lat"],
                lon=geo["lon"],
                source_type=geo["source_type"]
            )

            db.session.add(event)
            db.session.commit()

            emit_security_event(event)

            return event

        except Exception as e:
            db.session.rollback()
            print("DB ERROR:", e)
            return None

    def auto_block(ip):
        count = SecurityEvent.query.filter_by(ip_address=ip).count()

        if count >= 3:
            if not BlockedIP.query.filter_by(ip_address=ip).first():
                db.session.add(BlockedIP(ip_address=ip))
                db.session.commit()
                print("🚫 BLOCKED:", ip)

    def detect_attack(data):
        for attack_type, patterns in ATTACK_RULES.items():
            for pattern in patterns:
                try:
                    if re.search(pattern, data, re.IGNORECASE):
                        return attack_type, pattern
                except re.error as e:
                    print(f"BAD REGEX IN {attack_type}: {pattern} -> {e}")
        return None, None

    @app.before_request
    def waf():
        ip = get_ip()

        bypass_paths = [
            "/static",
            "/socket.io",
            "/api/soc-data",
            "/favicon.ico"
        ]

        if any(request.path.startswith(path) for path in bypass_paths):
            return

        if BlockedIP.query.filter_by(ip_address=ip).first():
            return "🚫 Your IP is blocked", 403

        raw = " ".join([
            request.path,
            request.full_path,
            request.query_string.decode(errors="ignore"),
            request.get_data(as_text=True)
        ])

        data = normalize(raw)

        attack, matched_rule = detect_attack(data)

        if attack:
            print(f"🚨 BLOCKED: {attack} | Rule: {matched_rule}")

            log_event(ip, attack, data)
            send_alert(ip, attack, data)
            auto_block(ip)

            return render_template("403.html"), 403

    @app.route("/api/soc-data")
    def soc_data():
        events = SecurityEvent.query.order_by(SecurityEvent.id.desc()).limit(50).all()
        return jsonify([serialize_event(event) for event in events])

    @socketio.on("connect")
    def handle_connect():
        print("✅ Client connected to live SOC socket")
        events = SecurityEvent.query.order_by(SecurityEvent.id.desc()).limit(20).all()
        socketio.emit("soc_snapshot", [serialize_event(event) for event in events])

    @socketio.on("disconnect")
    def handle_disconnect():
        print("❌ Client disconnected from live SOC socket")

    @app.route("/unblock-all")
    def unblock_all():
        try:
            db.session.query(BlockedIP).delete()
            db.session.commit()
            return "✅ All IPs unblocked"
        except Exception as e:
            return str(e)

    from routes.main import main_bp
    from routes.contact import contact_bp
    from routes.auth import auth_bp
    from routes.admin import admin_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(contact_bp)
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(admin_bp, url_prefix="/admin")

    with app.app_context():
        db.create_all()

        try:
            columns = db.session.execute(text("PRAGMA table_info(security_events)")).fetchall()
            existing_columns = [col[1] for col in columns]

            upgrades = {
                "country": "ALTER TABLE security_events ADD COLUMN country VARCHAR(120) DEFAULT 'Unknown'",
                "city": "ALTER TABLE security_events ADD COLUMN city VARCHAR(120) DEFAULT ''",
                "lat": "ALTER TABLE security_events ADD COLUMN lat FLOAT DEFAULT 20.5937",
                "lon": "ALTER TABLE security_events ADD COLUMN lon FLOAT DEFAULT 78.9629",
                "source_type": "ALTER TABLE security_events ADD COLUMN source_type VARCHAR(50) DEFAULT 'External'"
            }

            for column, sql in upgrades.items():
                if column not in existing_columns:
                    db.session.execute(text(sql))

            db.session.commit()

        except Exception as e:
            db.session.rollback()
            print("DB UPGRADE SKIPPED/ERROR:", e)

    return app


app = create_app()

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)