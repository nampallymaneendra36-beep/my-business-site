import re
import requests
from urllib.parse import unquote
from dotenv import load_dotenv

from flask import Flask, request, render_template, jsonify
from flask_login import LoginManager
from flask_mail import Message

from config import Config
from extensions import db, mail
from models import User, SecurityEvent, BlockedIP

load_dotenv()


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    print("🚨 PPC WAF + SOC + GEOIP + EMAIL ACTIVE")

    db.init_app(app)
    mail.init_app(app)

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
            or ip == "::1"
            or ip.startswith("192.168.")
            or ip.startswith("10.")
            or ip.startswith("172.16.")
            or ip.startswith("172.17.")
            or ip.startswith("172.18.")
            or ip.startswith("172.19.")
            or ip.startswith("172.20.")
            or ip.startswith("172.21.")
            or ip.startswith("172.22.")
            or ip.startswith("172.23.")
            or ip.startswith("172.24.")
            or ip.startswith("172.25.")
            or ip.startswith("172.26.")
            or ip.startswith("172.27.")
            or ip.startswith("172.28.")
            or ip.startswith("172.29.")
            or ip.startswith("172.30.")
            or ip.startswith("172.31.")
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

            response = requests.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon,message",
                timeout=3
            )
            result = response.json()

            if result.get("status") != "success":
                return {
                    "country": "Unknown",
                    "city": "",
                    "lat": 20.5937,
                    "lon": 78.9629,
                    "source_type": "External"
                }

            return {
                "country": result.get("country", "Unknown"),
                "city": result.get("city", ""),
                "lat": result.get("lat", 20.5937),
                "lon": result.get("lon", 78.9629),
                "source_type": "External"
            }

        except Exception as e:
            print("GEO ERROR:", e)
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

        score = 0
        category = "Unknown"
        action = "Monitor traffic"

        if "javascript" in payload or "<script" in payload or "alert" in payload or "onerror" in payload:
            score = 90
            category = "Cross-Site Scripting (XSS)"
            action = "Block IP, sanitize input, review affected page"

        elif "union" in payload or "or 1=1" in payload or "drop table" in payload:
            score = 85
            category = "SQL Injection"
            action = "Block IP, review database logs, validate parameterized queries"

        elif "cmd=" in payload or "powershell" in payload or "curl" in payload or "wget" in payload:
            score = 80
            category = "Command Injection"
            action = "Block IP, isolate host, review command execution paths"

        elif "../" in payload or "..\\" in payload or "etc/passwd" in payload:
            score = 70
            category = "Path Traversal"
            action = "Block IP, check file access logs, validate path handling"

        elif attack == "xss":
            score = 75
            category = "Cross-Site Scripting (XSS)"
            action = "Review payload and sanitize user input"

        elif attack == "sqli":
            score = 80
            category = "SQL Injection"
            action = "Review database access and input validation"

        elif attack == "command injection":
            score = 80
            category = "Command Injection"
            action = "Review server command execution risk"

        else:
            score = 40
            category = "Suspicious Activity"
            action = "Monitor traffic and review logs"

        if score >= 85:
            severity = "Critical"
        elif score >= 70:
            severity = "High"
        elif score >= 50:
            severity = "Medium"
        else:
            severity = "Low"

        return severity, score, category, action

    def send_alert(ip, attack, payload):
        email = app.config.get("MAIL_USERNAME")

        try:
            msg = Message(
                subject=f"🚨 Attack Detected: {attack}",
                sender=email,
                recipients=[email],
                body=f"""
Attack Detected!

IP: {ip}
Type: {attack}

Payload:
{payload}
"""
            )
            mail.send(msg)
            print("📧 EMAIL SENT")
        except Exception as e:
            print("❌ EMAIL ERROR:", e)

    def log_event(ip, attack, payload):
        try:
            event = SecurityEvent(
                ip_address=ip,
                path=request.path,
                method=request.method,
                attack_type=attack,
                payload=payload[:1000]
            )
            db.session.add(event)
            db.session.commit()
            print("📊 EVENT LOGGED")
        except Exception as e:
            db.session.rollback()
            print("DB ERROR:", e)

    def auto_block(ip):
        count = SecurityEvent.query.filter_by(ip_address=ip).count()
        print(f"⚠️ {ip} attack count:", count)

        if count >= 3:
            existing = BlockedIP.query.filter_by(ip_address=ip).first()

            if not existing:
                db.session.add(BlockedIP(ip_address=ip))
                db.session.commit()
                print("🚫 AUTO BLOCKED:", ip)

    @app.before_request
    def waf():
        ip = get_ip()

        if BlockedIP.query.filter_by(ip_address=ip).first():
            print("🚫 BLOCKED IP ACCESS:", ip)
            return "🚫 Your IP is blocked by WAF", 403

        raw = " ".join([
            request.path,
            request.full_path,
            request.query_string.decode(errors="ignore"),
            request.get_data(as_text=True)
        ])

        data = normalize(raw)

        rules = {
            r"javascript:": "XSS",
            r"alert\s*\(": "XSS",
            r"<script": "XSS",
            r"onerror=": "XSS",
            r"union\s+select": "SQLi",
            r"or\s+1=1": "SQLi",
            r"\.\./": "Traversal",
            r"cmd=": "Command Injection",
            r"powershell": "Command Injection",
            r"curl\s+": "Command Injection",
            r"wget\s+": "Command Injection"
        }

        for pattern, attack in rules.items():
            if re.search(pattern, data):
                print("🚨 BLOCKED:", attack)

                log_event(ip, attack, data)
                send_alert(ip, attack, data)
                auto_block(ip)

                return render_template("403.html"), 403

    @app.route("/api/soc-data")
    def soc_data():
        events = SecurityEvent.query.order_by(SecurityEvent.id.desc()).limit(20).all()
        data = []

        for e in events:
            geo = get_geo(e.ip_address)
            severity, score, category, action = analyze_threat(e.payload, e.attack_type)

            data.append({
                "id": e.id,
                "time": e.timestamp.strftime("%Y-%m-%d %H:%M:%S") if e.timestamp else "",
                "ip": e.ip_address,
                "attack": e.attack_type,
                "path": e.path,
                "method": e.method,
                "payload": e.payload,

                "severity": severity,
                "score": score,
                "category": category,
                "action": action,

                "country": geo["country"],
                "city": geo["city"],
                "lat": geo["lat"],
                "lon": geo["lon"],
                "source_type": geo["source_type"],
                "geo_label": f"{geo['country']} {geo['city']}".strip()
            })

        return jsonify(data)

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

    return app


app = create_app()

if __name__ == "__main__":
    app.run(port=5000)