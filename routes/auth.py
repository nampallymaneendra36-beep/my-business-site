from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy import or_
from extensions import db
from models import User, LoginAudit

auth_bp = Blueprint("auth", __name__)


def get_client_ip():
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"


def save_login_audit(user_id, email, status):
    try:
        log = LoginAudit(
            user_id=user_id,
            email=email,
            ip_address=get_client_ip(),
            user_agent=request.headers.get("User-Agent", ""),
            status=status
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print("LOGIN AUDIT ERROR:", e)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        if not username or not email or not password:
            flash("All fields are required.", "error")
            return render_template("register.html")

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template("register.html")

        existing_user = User.query.filter(
            or_(User.username == username, User.email == email)
        ).first()

        if existing_user:
            flash("Username or email already exists.", "error")
            return render_template("register.html")

        new_user = User(username=username, email=email)
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful. Please login.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for("main.dashboard"))
        elif current_user.has_role("analyst"):
            return redirect(url_for("main.soc_dashboard"))
        else:
            return redirect(url_for("main.my_requests"))

    if request.method == "POST":
        login_input = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()

        user = User.query.filter(
            or_(User.email == login_input.lower(), User.username == login_input)
        ).first()

        if user and user.check_password(password):
            login_user(user)
            save_login_audit(user.id, user.email, "SUCCESS")

            flash("Login successful.", "success")

            if user.is_admin:
                return redirect(url_for("main.dashboard"))
            elif user.has_role("analyst"):
                return redirect(url_for("main.soc_dashboard"))
            else:
                return redirect(url_for("main.my_requests"))

        save_login_audit(None, login_input, "FAILED")
        flash("Invalid email/username or password.", "error")

    return render_template("login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    save_login_audit(current_user.id, current_user.email, "LOGOUT")

    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("main.index"))