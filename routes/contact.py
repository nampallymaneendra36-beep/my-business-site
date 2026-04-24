from flask import Blueprint, render_template, request, flash
from flask_login import current_user
from extensions import db, mail
from models import ContactMessage
from flask_mail import Message

contact_bp = Blueprint("contact", __name__)


@contact_bp.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        subject = request.form.get("subject")
        message_text = request.form.get("message")

        if not name or not email or not subject or not message_text:
            flash("All fields are required.", "error")
            return render_template("contact.html")

        # ✅ Save message with user_id
        message = ContactMessage(
            name=name,
            email=email,
            subject=subject,
            message=message_text,
            user_id=current_user.id if current_user.is_authenticated else None
        )

        db.session.add(message)
        db.session.commit()

        # ADMIN EMAIL
        try:
            admin_msg = Message(
                subject=f"🚨 New Lead: {subject}",
                recipients=["admin@ppcyber.com"]
            )

            admin_msg.body = f"""
New Lead Received!

Name: {name}
Email: {email}
Subject: {subject}

Message:
{message_text}
"""
            mail.send(admin_msg)

        except Exception as e:
            print("ADMIN EMAIL ERROR:", e)

        # USER EMAIL
        try:
            user_msg = Message(
                subject="We received your request",
                recipients=[email]
            )

            user_msg.body = f"""
Hi {name},

We received your request and will respond soon.

Your Message:
{message_text}
"""
            mail.send(user_msg)

        except Exception as e:
            print("USER EMAIL ERROR:", e)

        flash("Message sent successfully!", "success")

    return render_template("contact.html")