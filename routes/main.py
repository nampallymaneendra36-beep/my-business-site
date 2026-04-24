import os
from flask import Blueprint, render_template, abort, redirect, url_for, flash, request
from flask_login import login_required, current_user
from sqlalchemy import text
from extensions import db
from models import ContactMessage

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
        abort(403)

    status_filter = request.args.get("status", "All")

    query = ContactMessage.query.order_by(ContactMessage.submitted_at.desc())

    if status_filter in ["New", "In Progress", "Closed"]:
        query = query.filter_by(status=status_filter)

    messages = query.all()

    total_count = ContactMessage.query.count()
    new_count = ContactMessage.query.filter_by(status="New").count()
    progress_count = ContactMessage.query.filter_by(status="In Progress").count()
    closed_count = ContactMessage.query.filter_by(status="Closed").count()

    return render_template(
        "dashboard.html",
        messages=messages,
        status_filter=status_filter,
        total_count=total_count,
        new_count=new_count,
        progress_count=progress_count,
        closed_count=closed_count
    )


@main_bp.route("/message/<int:message_id>/read")
@login_required
def mark_message_read(message_id):
    if not current_user.is_admin:
        abort(403)

    message = ContactMessage.query.get_or_404(message_id)
    message.is_read = True
    db.session.commit()

    flash("Message marked as read.", "success")
    return redirect(url_for("main.dashboard"))


@main_bp.route("/message/<int:message_id>/status/<status>")
@login_required
def update_message_status(message_id, status):
    if not current_user.is_admin:
        abort(403)

    allowed_statuses = {
        "new": "New",
        "progress": "In Progress",
        "closed": "Closed"
    }

    if status not in allowed_statuses:
        abort(404)

    message = ContactMessage.query.get_or_404(message_id)
    message.status = allowed_statuses[status]
    message.is_read = True
    db.session.commit()

    flash(f"Lead status updated to {message.status}.", "success")
    return redirect(url_for("main.dashboard"))


@main_bp.route("/message/<int:message_id>/delete")
@login_required
def delete_message(message_id):
    if not current_user.is_admin:
        abort(403)

    message = ContactMessage.query.get_or_404(message_id)
    db.session.delete(message)
    db.session.commit()

    flash("Lead deleted successfully.", "success")
    return redirect(url_for("main.dashboard"))


@main_bp.route("/admin-db-upgrade")
def admin_db_upgrade():
    token = request.args.get("token")
    expected_token = os.environ.get("ADMIN_SETUP_TOKEN")

    if not expected_token or token != expected_token:
        abort(403)

    try:
        engine_name = db.engine.name

        if engine_name == "postgresql":
            db.session.execute(
                text(
                    "ALTER TABLE contact_messages "
                    "ADD COLUMN IF NOT EXISTS status VARCHAR(30) DEFAULT 'New' NOT NULL"
                )
            )
        elif engine_name == "sqlite":
            columns = db.session.execute(text("PRAGMA table_info(contact_messages)")).fetchall()
            column_names = [column[1] for column in columns]

            if "status" not in column_names:
                db.session.execute(
                    text("ALTER TABLE contact_messages ADD COLUMN status VARCHAR(30) DEFAULT 'New' NOT NULL")
                )

        db.session.commit()
        return "Database upgraded successfully."

    except Exception as e:
        db.session.rollback()
        return f"Database upgrade failed: {str(e)}", 500
    
    from flask_login import login_required, current_user
from models import ContactMessage


@main_bp.route("/my-requests")
@login_required
def my_requests():
    messages = ContactMessage.query.filter_by(user_id=current_user.id).order_by(
        ContactMessage.submitted_at.desc()
    ).all()

    return render_template("my_requests.html", messages=messages)