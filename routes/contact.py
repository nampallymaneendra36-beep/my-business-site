from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import current_user
from extensions import db, mail
from models import ContactMessage
from utils.ai_agent import analyze_lead

contact_bp = Blueprint("contact", __name__)


@contact_bp.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        subject = request.form.get("subject")
        message_text = request.form.get("message")

        # ✅ AI analysis
        ai = analyze_lead(subject, message_text)

        new_message = ContactMessage(
            name=name,
            email=email,
            subject=subject,
            message=message_text,
            user_id=current_user.id if current_user.is_authenticated else None,
            ai_priority=ai["priority"],
            ai_category=ai["category"],
            ai_action=ai["action"]
        )

        db.session.add(new_message)
        db.session.commit()

        # ❌ TEMP: disable email to avoid crash
        try:
            if mail:
                print("Mail configured")
        except Exception as e:
            print("MAIL ERROR:", e)

        flash("Message sent successfully!", "success")
        return redirect(url_for("contact.contact"))

    return render_template("contact.html")