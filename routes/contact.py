from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import current_user
from extensions import db
from models import ContactMessage
from utils.ai_agent import analyze_lead

contact_bp = Blueprint("contact", __name__)


@contact_bp.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        try:
            name = request.form.get("name", "").strip()
            email = request.form.get("email", "").strip()
            subject = request.form.get("subject", "").strip()
            message_text = request.form.get("message", "").strip()

            if not name or not email or not subject or not message_text:
                flash("All fields are required.", "error")
                return render_template("contact.html")

            ai = analyze_lead(subject, message_text)

            new_message = ContactMessage(
                name=name,
                email=email,
                subject=subject,
                message=message_text,
                user_id=current_user.id if current_user.is_authenticated else None,
                ai_priority=ai.get("priority"),
                ai_category=ai.get("category"),
                ai_action=ai.get("action")
            )

            db.session.add(new_message)
            db.session.commit()

            flash("Message sent successfully.", "success")
            return redirect(url_for("contact.contact"))

        except Exception as e:
            db.session.rollback()
            return f"CONTACT FORM ERROR: {str(e)}", 500

    return render_template("contact.html")