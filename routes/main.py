import os
from flask import Blueprint, render_template, abort, redirect, url_for, flash, request
from flask_login import login_required, current_user
from sqlalchemy import text
from extensions import db
from models import ContactMessage, User

main_bp = Blueprint("main", __name__)


# =========================
# BASIC ROUTES
# =========================

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


# =========================
# ADMIN DASHBOARD
# =========================

@main_bp.route("/dashboard")
@login_required
def dashboard():
    if not current_user.is_admin:
        return redirect(url_for("main.my_requests"))

    status_filter = request.args.get("status", "All")

    query = ContactMessage.query.order_by(ContactMessage.submitted_at.desc())

    if status_filter in ["New", "In Progress", "Closed"]:
        query = query.filter_by(status=status_filter)

    messages = query.all()

    return render_template(
        "dashboard.html",
        messages=messages,
        status_filter=status_filter,
        total_users=User.query.count(),
        total_leads=ContactMessage.query.count(),
        new_leads=ContactMessage.query.filter_by(status="New").count(),
        progress_leads=ContactMessage.query.filter_by(status="In Progress").count(),
        closed_leads=ContactMessage.query.filter_by(status="Closed").count()
    )


# =========================
# USER REQUESTS
# =========================

@main_bp.route("/my-requests")
@login_required
def my_requests():
    messages = ContactMessage.query.filter_by(
        user_id=current_user.id
    ).order_by(ContactMessage.submitted_at.desc()).all()

    return render_template("my_requests.html", messages=messages)


# =========================
# LEAD ACTIONS
# =========================

@main_bp.route("/lead/<int:lead_id>/status/<status>")
@login_required
def update_lead_status(lead_id, status):
    if not current_user.is_admin:
        abort(403)

    status_map = {
        "new": "New",
        "progress": "In Progress",
        "closed": "Closed"
    }

    if status not in status_map:
        abort(404)

    lead = ContactMessage.query.get_or_404(lead_id)
    lead.status = status_map[status]
    lead.is_read = True

    db.session.commit()

    flash(f"Lead status updated to {lead.status}.", "success")
    return redirect(url_for("main.dashboard"))


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


# =========================
# 🔥 SAFE DATABASE UPGRADE ROUTE
# =========================

@main_bp.route("/admin-db-upgrade")
def admin_db_upgrade():
    token = request.args.get("token")

    # Optional security check
    expected_token = os.environ.get("ADMIN_SETUP_TOKEN", "ppc-admin-upgrade-2026")

    if token != expected_token:
        abort(403)

    try:
        # ✅ Add missing columns safely
        db.session.execute(text("""
            ALTER TABLE contact_messages 
            ADD COLUMN IF NOT EXISTS ai_priority VARCHAR(50)
        """))

        db.session.execute(text("""
            ALTER TABLE contact_messages 
            ADD COLUMN IF NOT EXISTS ai_category VARCHAR(100)
        """))

        db.session.execute(text("""
            ALTER TABLE contact_messages 
            ADD COLUMN IF NOT EXISTS ai_action VARCHAR(200)
        """))

        db.session.commit()

        return "Database upgraded successfully."

    except Exception as e:
        db.session.rollback()
        return f"Upgrade failed: {str(e)}"