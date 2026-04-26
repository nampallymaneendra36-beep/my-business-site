from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required, current_user
from extensions import db
from models import User, ContactMessage

admin_bp = Blueprint("admin", __name__)


def is_admin():
    return current_user.is_authenticated and current_user.is_admin


@admin_bp.route("/")
@login_required
def admin_dashboard():
    if not is_admin():
        flash("Admin access required.")
        return redirect(url_for("main.index"))

    messages = ContactMessage.query.order_by(ContactMessage.submitted_at.desc()).all()

    total_users = User.query.count()
    total_leads = ContactMessage.query.count()
    new_leads = ContactMessage.query.filter_by(status="New").count()
    in_progress = ContactMessage.query.filter_by(status="In Progress").count()
    closed = ContactMessage.query.filter_by(status="Closed").count()

    return render_template(
        "admin_dashboard.html",
        messages=messages,
        total_users=total_users,
        total_leads=total_leads,
        new_leads=new_leads,
        in_progress=in_progress,
        closed=closed
    )


@admin_bp.route("/message/<int:message_id>/mark-read")
@login_required
def mark_read(message_id):
    if not is_admin():
        flash("Admin access required.")
        return redirect(url_for("main.index"))

    message = ContactMessage.query.get_or_404(message_id)
    message.status = "Read"
    db.session.commit()

    flash("Message marked as read.")
    return redirect(url_for("admin.admin_dashboard"))


@admin_bp.route("/message/<int:message_id>/status/<status>")
@login_required
def set_status(message_id, status):
    if not is_admin():
        flash("Admin access required.")
        return redirect(url_for("main.index"))

    allowed_statuses = ["New", "In Progress", "Closed", "Read"]

    if status not in allowed_statuses:
        flash("Invalid status.")
        return redirect(url_for("admin.admin_dashboard"))

    message = ContactMessage.query.get_or_404(message_id)
    message.status = status
    db.session.commit()

    flash(f"Status updated to {status}.")
    return redirect(url_for("admin.admin_dashboard"))


@admin_bp.route("/delete/<int:id>")
@login_required
def delete_message(id):
    if not is_admin():
        flash("Admin access required.")
        return redirect(url_for("main.index"))

    message = ContactMessage.query.get_or_404(id)
    db.session.delete(message)
    db.session.commit()

    flash("Message deleted.")
    return redirect(url_for("admin.admin_dashboard"))