import os
from flask import Blueprint, render_template, abort, request
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
    return render_template("dashboard.html")


@main_bp.route("/my-requests")
@login_required
def my_requests():
    messages = ContactMessage.query.filter_by(user_id=current_user.id).order_by(
        ContactMessage.submitted_at.desc()
    ).all()

    return render_template("my_requests.html", messages=messages)


@main_bp.route("/admin-db-upgrade")
def admin_db_upgrade():
    token = request.args.get("token")
    expected_token = os.environ.get("ADMIN_SETUP_TOKEN")

    if not expected_token or token != expected_token:
        abort(403)

    try:
        db.session.execute(
            text(
                "ALTER TABLE contact_messages "
                "ADD COLUMN IF NOT EXISTS status VARCHAR(30) DEFAULT 'New' NOT NULL"
            )
        )

        db.session.execute(
            text(
                "ALTER TABLE contact_messages "
                "ADD COLUMN IF NOT EXISTS user_id INTEGER"
            )
        )

        db.session.commit()
        return "Database upgraded successfully."

    except Exception as e:
        db.session.rollback()
        return f"Database upgrade failed: {str(e)}", 500