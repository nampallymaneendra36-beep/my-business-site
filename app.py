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

    print("🚨 PPC WAF + SOC + GEOIP + AI ACTIVE")

    db.init_app(app)
    mail.init_app(app)

    # ---------------- LOGIN ----------------
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # ---------------- HELPERS ----------------
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
        return ip.startswith(("127.", "192.168.", "10.", "172.")) or ip == "::1"

    # ---------------- GEOIP ----------------
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

            return {
                "country": res.get("country", "Unknown"),
                "city": res.get("city", ""),
                "lat": res.get("lat", 20.5937),
                "lon": res.get("lon", 78.9629),
                "source_type": "External"
            }

        except:
            return {
                "country": "Unknown",
                "city": "",
                "lat": 20.5937,
                "lon": 78.9629,
                "source_type": "External"
            }

    # ---------------- AI THREAT ----------------
    def analyze_threat(payload, attack):
        payload = str(payload or "").lower()

        if "javascript" in payload or "<script" in payload:
            return "Critical", 90, "Cross-Site Scripting (XSS)", "Block IP, sanitize input"
        elif "union" in payload or "or 1=1" in payload:
            return "Critical", 85, "SQL Injection", "Block IP, review DB"
        elif "cmd=" in payload or "powershell" in payload:
            return "High", 80, "Command Injection", "Block IP, check server"
        elif "../" in payload:
            return "High", 70, "Path Traversal", "Validate file access"
        else:
            return "Medium", 40, "Suspicious Activity", "Monitor logs"

    # ---------------- EMAIL ----------------
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

    # ---------------- LOG ----------------
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
        except Exception as e:
            db.session.rollback()
            print("DB ERROR:", e)

    # ---------------- AUTO BLOCK ----------------
    def auto_block(ip):
        count = SecurityEvent.query.filter_by(ip_address=ip).count()

        if count >= 3:
            if not BlockedIP.query.filter_by(ip_address=ip).first():
                db.session.add(BlockedIP(ip_address=ip))
                db.session.commit()
                print("🚫 BLOCKED:", ip)

    # ---------------- WAF ----------------
    @app.before_request
    def waf():
        ip = get_ip()

        # skip static files
        if request.path.startswith("/static"):
            return

        # check block
        if BlockedIP.query.filter_by(ip_address=ip).first():
            return "🚫 Your IP is blocked", 403

        raw = " ".join([
            request.path,
            request.full_path,
            request.query_string.decode(errors="ignore"),
            request.get_data(as_text=True)
        ])

        data = normalize(raw)

        rules = {
            r"javascript:": "XSS",
            r"<script": "XSS",
            r"alert\s*\(": "XSS",
            r"union\s+select": "SQLi",
            r"or\s+1=1": "SQLi",
            r"\.\./": "Traversal",
            r"cmd=": "Command Injection"
        }

        for pattern, attack in rules.items():
            if re.search(pattern, data):
                log_event(ip, attack, data)
                send_alert(ip, attack, data)
                auto_block(ip)
                return render_template("403.html"), 403

    # ---------------- API ----------------
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
                "geo_label": f"{geo['country']} {geo['city']}".strip()
            })

        return jsonify(data)

    # ---------------- UNBLOCK ROUTE ----------------
    @app.route("/unblock-all")
    def unblock_all():
        try:
            db.session.query(BlockedIP).delete()
            db.session.commit()
            return "✅ All IPs unblocked"
        except Exception as e:
            return str(e)

    # ---------------- ROUTES ----------------
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