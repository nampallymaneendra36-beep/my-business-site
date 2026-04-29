import os
from flask import Blueprint, render_template, abort, redirect, url_for, flash, request, Response
from flask_login import login_required, current_user
from sqlalchemy import text, func
from extensions import db
from models import ContactMessage, User, SecurityEvent, BlockedIP, LoginAudit

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

    status_filter = request.args.get("status", "All").strip()
    query = ContactMessage.query

    if status_filter in ["New", "In Progress", "Closed"]:
        query = query.filter(
            func.lower(func.trim(ContactMessage.status)) == status_filter.lower()
        )

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
        new_leads=ContactMessage.query.filter(
            func.lower(func.trim(ContactMessage.status)) == "new"
        ).count(),
        progress_leads=ContactMessage.query.filter(
            func.lower(func.trim(ContactMessage.status)) == "in progress"
        ).count(),
        closed_leads=ContactMessage.query.filter(
            func.lower(func.trim(ContactMessage.status)) == "closed"
        ).count()
    )


@main_bp.route("/admin/login-audit")
@login_required
def login_audit():
    if not current_user.is_admin:
        abort(403)

    logs = LoginAudit.query.order_by(LoginAudit.timestamp.desc()).limit(200).all()
    return render_template("login_audit.html", logs=logs)


def get_geo_info(event):
    country = getattr(event, "country", None) or "Unknown"
    city = getattr(event, "city", None) or ""
    source_type = getattr(event, "source_type", None) or "External"
    ip = event.ip_address or ""

    if ip.startswith("127.") or ip == "::1" or ip.startswith("192.168.") or ip.startswith("10."):
        country = "Localhost"
        city = "Internal"
        source_type = "Internal"

    return country, city, source_type


def analyze_threat(event):
    payload = str(event.payload or "").lower()
    attack = str(event.attack_type or "").lower()

    score = 40
    category = "Suspicious Activity"
    action = "Monitor traffic and review logs"

    if "javascript" in payload or "<script" in payload or "alert" in payload or "onerror" in payload or attack == "xss":
        score = 90
        category = "Cross-Site Scripting (XSS)"
        action = "Block IP, sanitize input, review affected page"

    elif "union" in payload or "or 1=1" in payload or "drop table" in payload or attack == "sqli":
        score = 85
        category = "SQL Injection"
        action = "Block IP, review database logs, validate parameterized queries"

    elif "cmd=" in payload or "powershell" in payload or "curl" in payload or "wget" in payload or attack == "command injection":
        score = 80
        category = "Command Injection"
        action = "Block IP, isolate host, review command execution paths"

    elif "../" in payload or "..\\" in payload or "etc/passwd" in payload or attack == "traversal":
        score = 70
        category = "Path Traversal"
        action = "Block IP, check file access logs, validate path handling"

    if score >= 85:
        severity = "Critical"
    elif score >= 70:
        severity = "High"
    elif score >= 50:
        severity = "Medium"
    else:
        severity = "Low"

    return severity, score, category, action


def format_event(event):
    country, city, source_type = get_geo_info(event)
    severity, score, category, action = analyze_threat(event)

    return {
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
        "city": city,
        "source_type": source_type
    }


@main_bp.route("/soc")
@login_required
def soc_dashboard():
    if not current_user.has_role("admin", "analyst"):
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
            str(event.payload or ""),
            str(getattr(event, "country", "") or ""),
            str(getattr(event, "city", "") or "")
        ]).lower()

        if not search or search in combined:
            filtered_events.append(format_event(event))

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


@main_bp.route("/soc/history")
@login_required
def attack_history():
    if not current_user.has_role("admin", "analyst"):
        abort(403)

    search = request.args.get("search", "").strip()
    ip_filter = request.args.get("ip", "").strip()
    attack_filter = request.args.get("attack", "").strip()
    severity_filter = request.args.get("severity", "").strip()
    start_filter = request.args.get("start", "").strip()
    end_filter = request.args.get("end", "").strip()

    events = SecurityEvent.query.order_by(SecurityEvent.timestamp.desc()).all()
    history = []

    for event in events:
        formatted = format_event(event)

        combined = " ".join([
            str(formatted["ip"] or ""),
            str(formatted["attack"] or ""),
            str(formatted["path"] or ""),
            str(formatted["method"] or ""),
            str(formatted["payload"] or ""),
            str(formatted["country"] or ""),
            str(formatted["city"] or ""),
            str(formatted["severity"] or "")
        ]).lower()

        if search and search.lower() not in combined:
            continue

        if ip_filter and ip_filter not in str(formatted["ip"] or ""):
            continue

        if attack_filter and attack_filter != formatted["attack"]:
            continue

        if severity_filter and severity_filter != formatted["severity"]:
            continue

        event_date = event.timestamp.strftime("%Y-%m-%d") if event.timestamp else ""

        if start_filter and event_date < start_filter:
            continue

        if end_filter and event_date > end_filter:
            continue

        history.append(formatted)

    attack_types = sorted(list(set([e.attack_type for e in events if e.attack_type])))

    return render_template(
        "attack_history.html",
        events=history,
        filters={
            "search": search,
            "ip": ip_filter,
            "attack": attack_filter,
            "severity": severity_filter,
            "start": start_filter,
            "end": end_filter
        },
        attack_types=attack_types
    )


@main_bp.route("/soc/history/export")
@login_required
def export_attack_history():
    if not current_user.has_role("admin", "analyst"):
        abort(403)

    events = SecurityEvent.query.order_by(SecurityEvent.timestamp.desc()).all()

    csv_data = "Time,IP,Country,City,Source,Method,Path,Attack,Severity,Score,Category,Action,Payload\n"

    for event in events:
        formatted = format_event(event)
        time_value = event.timestamp.strftime("%Y-%m-%d %H:%M:%S") if event.timestamp else ""

        row = [
            time_value,
            str(formatted["ip"] or ""),
            str(formatted["country"] or ""),
            str(formatted["city"] or ""),
            str(formatted["source_type"] or ""),
            str(formatted["method"] or ""),
            str(formatted["path"] or ""),
            str(formatted["attack"] or ""),
            str(formatted["severity"] or ""),
            str(formatted["score"] or ""),
            str(formatted["category"] or ""),
            str(formatted["action"] or ""),
            str(formatted["payload"] or "").replace("\n", " ").replace(",", " ")
        ]

        csv_data += ",".join(row) + "\n"

    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=attack_history.csv"}
    )


@main_bp.route("/admin/users")
@login_required
def manage_users():
    if not current_user.is_admin:
        abort(403)

    users = User.query.order_by(User.id.asc()).all()
    return render_template("user_roles.html", users=users)


@main_bp.route("/admin/set-role/<int:user_id>/<role>", methods=["POST"])
@login_required
def set_role(user_id, role):
    if not current_user.is_admin:
        abort(403)

    allowed_roles = ["user", "analyst", "admin"]

    if role not in allowed_roles:
        abort(404)

    user = User.query.get_or_404(user_id)

    if user.id == current_user.id and role != "admin":
        flash("You cannot downgrade your own admin role.", "error")
        return redirect(url_for("main.manage_users"))

    if user.is_admin and role != "admin":
        admin_count = User.query.filter_by(is_admin=True).count()

        if admin_count <= 1:
            flash("At least one admin must exist.", "error")
            return redirect(url_for("main.manage_users"))

    user.role = role
    user.is_admin = True if role == "admin" else False

    db.session.commit()

    flash(f"{user.username} role updated to {role}.", "success")
    return redirect(url_for("main.manage_users"))


@main_bp.route("/unblock/<ip>")
@login_required
def unblock_ip(ip):
    if not current_user.has_role("admin", "analyst"):
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


@main_bp.route("/lead/<int:lead_id>/unread")
@login_required
def mark_lead_unread(lead_id):
    if not current_user.is_admin:
        abort(403)

    lead = ContactMessage.query.get_or_404(lead_id)
    lead.is_read = False
    db.session.commit()

    flash("Lead marked as unread.", "success")
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
