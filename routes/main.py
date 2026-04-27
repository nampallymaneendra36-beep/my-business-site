import os
from flask import Blueprint, render_template, abort, redirect, url_for, flash, request
from flask_login import login_required, current_user
from sqlalchemy import text
from extensions import db
from models import ContactMessage, User, SecurityEvent, BlockedIP

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
@main_bp.route("/home")
def index():
    return render_template("index.html")


@main_bp.route("/about")
def about():
    return render_template("about.html")


@main_bp.route("/services")
def services():
    return render_template("services.html")


@main_bp.route("/dashboard")
@login_required
def dashboard():
    if not current_user.is_admin:
        return redirect(url_for("main.my_requests"))

    status_filter = request.args.get("status", "All")
    query = ContactMessage.query

    if status_filter in ["New", "In Progress", "Closed"]:
        query = query.filter_by(status=status_filter)

    query = query.order_by(
        db.case(
            (ContactMessage.ai_priority == "High", 1),
            (ContactMessage.ai_priority == "Medium", 2),
            (ContactMessage.ai_priority == "Low", 3),
            else_=4
        ),
        ContactMessage.submitted_at.desc()
    )

    messages = query.all()

    return render_template(
        "dashboard.html",
        messages=messages,
        status_filter=status_filter,
        total_users=User.query.count(),
        total_leads=ContactMessage.query.count(),
        new_leads=ContactMessage.query.filter(ContactMessage.status == "New").count(),
        progress_leads=ContactMessage.query.filter(ContactMessage.status == "In Progress").count(),
        closed_leads=ContactMessage.query.filter(ContactMessage.status == "Closed").count()
    )


@main_bp.route("/make-admin")
def make_admin():
    token = request.args.get("token")
    email = request.args.get("email")

    expected_token = os.environ.get("ADMIN_SETUP_TOKEN", "ppc-admin-upgrade-2026")

    if token != expected_token:
        abort(403)

    if not email:
        return "Missing email. Use /make-admin?email=your@email.com&token=ppc-admin-upgrade-2026", 400

    user = User.query.filter_by(email=email).first()

    if not user:
        return f"No user found with email: {email}", 404

    user.is_admin = True

    if hasattr(user, "role"):
        user.role = "admin"

    db.session.commit()

    return f"✅ {email} is now admin"


def get_geo_info(ip):
    if not ip:
        return "Unknown", "Unknown"

    if ip.startswith("127.") or ip == "::1" or ip.startswith("192.168.") or ip.startswith("10."):
        return "Localhost", "Internal"

    return "Unknown", "External"


def analyze_threat(event):
    payload = str(event.payload or "").lower()
    attack = str(event.attack_type or "").lower()

    score = 0
    category = "Unknown"
    action = "Monitor"

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


@main_bp.route("/soc")
@login_required
def soc_dashboard():
    if not current_user.is_admin:
        abort(403)

    search = request.args.get("search", "").strip().lower()

    all_events = SecurityEvent.query.order_by(SecurityEvent.timestamp.desc()).all()
    blocked_ips = BlockedIP.query.order_by(BlockedIP.blocked_at.desc()).all()

    filtered_events = []

    for event in all_events:
        combined = " ".join([
            str(event.ip_address or ""),
            str(event.attack_type or ""),
            str(event.path or ""),
            str(event.method or ""),
            str(event.payload or "")
        ]).lower()

        if not search or search in combined:
            country, source_type = get_geo_info(event.ip_address)
            severity, score, category, action = analyze_threat(event)

            filtered_events.append({
                "time": event.timestamp,
                "ip": event.ip_address,
                "method": event.method,
                "path": event.path,
                "attack": event.attack_type,
                "payload": event.payload,
                "severity": severity,
                "score": score,
                "category": category,
                "action": action,
                "country": country,
                "source_type": source_type
            })

    xss_count = len([e for e in all_events if e.attack_type == "XSS"])
    sqli_count = len([e for e in all_events if e.attack_type == "SQLi"])
    command_count = len([e for e in all_events if e.attack_type == "Command Injection"])

    critical_count = len([e for e in all_events if analyze_threat(e)[0] == "Critical"])
    high_count = len([e for e in all_events if analyze_threat(e)[0] == "High"])
    medium_count = len([e for e in all_events if analyze_threat(e)[0] == "Medium"])

    total_events = len(all_events)

    xss_percent = int((xss_count / total_events) * 100) if total_events else 0
    sqli_percent = int((sqli_count / total_events) * 100) if total_events else 0
    command_percent = int((command_count / total_events) * 100) if total_events else 0

    return render_template(
        "soc_dashboard.html",
        events=filtered_events,
        blocked_ips=blocked_ips,
        total_events=total_events,
        xss_count=xss_count,
        sqli_count=sqli_count,
        command_count=command_count,
        blocked_count=len(blocked_ips),
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        xss_percent=xss_percent,
        sqli_percent=sqli_percent,
        command_percent=command_percent,
        search=search
    )


@main_bp.route("/unblock/<ip>")
@login_required
def unblock_ip(ip):
    if not current_user.is_admin:
        abort(403)

    blocked_ip = BlockedIP.query.filter_by(ip_address=ip).first()

    if blocked_ip:
        db.session.delete(blocked_ip)
        db.session.commit()
        flash(f"IP {ip} unblocked successfully.", "success")

    return redirect(url_for("main.soc_dashboard"))


@main_bp.route("/my-requests")
@login_required
def my_requests():
    messages = ContactMessage.query.filter_by(user_id=current_user.id).order_by(
        ContactMessage.submitted_at.desc()
    ).all()

    return render_template("my_requests.html", messages=messages)


@main_bp.route("/lead/<int:lead_id>/read")
@login_required
def mark_lead_read(lead_id):
    if not current_user.is_admin:
        abort(403)

    lead = ContactMessage.query.get_or_404(lead_id)
    lead.is_read = True
    db.session.commit()

    flash("Lead marked as read.", "success")
    return redirect(url_for("main.dashboard"))


@main_bp.route("/lead/<int:lead_id>/status/<status>")
@login_required
def update_lead_status(lead_id, status):
    if not current_user.is_admin:
        abort(403)

    allowed_statuses = {
        "new": "New",
        "progress": "In Progress",
        "closed": "Closed"
    }

    if status not in allowed_statuses:
        abort(404)

    lead = ContactMessage.query.get_or_404(lead_id)
    lead.status = allowed_statuses[status]
    lead.is_read = True
    db.session.commit()

    flash(f"Lead status updated to {lead.status}.", "success")
    return redirect(url_for("main.dashboard"))


@main_bp.route("/lead/<int:lead_id>/delete")
@login_required
def delete_lead(lead_id):
    if not current_user.is_admin:
        abort(403)

    lead = ContactMessage.query.get_or_404(lead_id)
    db.session.delete(lead)
    db.session.commit()

    flash("Lead deleted successfully.", "success")
    return redirect(url_for("main.dashboard"))


@main_bp.route("/admin-db-upgrade")
def admin_db_upgrade():
    token = request.args.get("token")
    expected_token = os.environ.get("ADMIN_SETUP_TOKEN", "ppc-admin-upgrade-2026")

    if token != expected_token:
        abort(403)

    try:
        db.session.execute(text("ALTER TABLE contact_messages ADD COLUMN is_read BOOLEAN DEFAULT 0"))
        db.session.execute(text("ALTER TABLE contact_messages ADD COLUMN status VARCHAR(50) DEFAULT 'New'"))
        db.session.execute(text("ALTER TABLE contact_messages ADD COLUMN user_id INTEGER"))
        db.session.execute(text("ALTER TABLE contact_messages ADD COLUMN ai_priority VARCHAR(50)"))
        db.session.execute(text("ALTER TABLE contact_messages ADD COLUMN ai_category VARCHAR(100)"))
        db.session.execute(text("ALTER TABLE contact_messages ADD COLUMN ai_action VARCHAR(200)"))

        db.session.commit()
        return "Database upgraded successfully."

    except Exception as e:
        db.session.rollback()
        return f"Database upgrade failed: {str(e)}", 500