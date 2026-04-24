import os
from flask import Blueprint, render_template, abort, redirect, url_for, flash
from flask_login import login_required, current_user
from extensions import db
from models import ContactMessage, User

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

    messages = ContactMessage.query.order_by(ContactMessage.submitted_at.desc()).all()
    return render_template("dashboard.html", messages=messages)


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


@main_bp.route("/message/<int:message_id>/delete")
@login_required
def delete_message(message_id):
    if not current_user.is_admin:
        abort(403)

    message = ContactMessage.query.get_or_404(message_id)
    db.session.delete(message)
    db.session.commit()

    flash("Message deleted successfully.", "success")
    return redirect(url_for("main.dashboard"))


@main_bp.route("/create-admin")
def create_admin():
    admin_email = "admin@ppcyber.com"
    admin_username = "admin"
    admin_password = os.environ.get("ADMIN_PASSWORD", "Admin@123")

    admin = User.query.filter_by(email=admin_email).first()

    if admin:
        admin.username = admin_username
        admin.is_admin = True
        admin.set_password(admin_password)
        db.session.commit()
        return "Admin already existed. Password updated successfully."

    admin = User(
        username=admin_username,
        email=admin_email,
        is_admin=True
    )

    admin.set_password(admin_password)

    db.session.add(admin)
    db.session.commit()

    return "Admin created successfully."