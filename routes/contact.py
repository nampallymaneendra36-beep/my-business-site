from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import current_user
from flask_mail import Message
from extensions import db, mail
from models import ContactMessage

contact_bp = Blueprint("contact", __name__)


@contact_bp.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        subject = request.form.get("subject", "").strip()
        message_text = request.form.get("message", "").strip()

        if not name or not email or not subject or not message_text:
            flash("All fields are required.", "error")
            return render_template("contact.html")

        lead = ContactMessage(
            name=name,
            email=email,
            subject=subject,
            message=message_text,
            user_id=current_user.id if current_user.is_authenticated else None
        )

        db.session.add(lead)
        db.session.commit()

        try:
            admin_email = Message(
                subject=f"🚨 New Lead: {subject}",
                recipients=["pureprosperitycyber@gmail.com"],
                reply_to=email,
                body=f"""New lead received.

Name: {name}
Email: {email}
Subject: {subject}

Message:
{message_text}

View dashboard:
https://my-business-site-1gei.onrender.com/dashboard
"""
            )
            mail.send(admin_email)
            print("ADMIN EMAIL SENT")
        except Exception as e:
            print("ADMIN EMAIL ERROR:", e)

        try:
            customer_email = Message(
                subject="We received your request | Pure Prosperity Cyber",
                recipients=[email],
                body=f"""Hi {name},

Thank you for contacting Pure Prosperity Cyber.

We received your request regarding:
{subject}

Our team will review it and get back to you soon.

Best regards,
Pure Prosperity Cyber
pureprosperitycyber@gmail.com
"""
            )
            mail.send(customer_email)
            print("CUSTOMER EMAIL SENT")
        except Exception as e:
            print("CUSTOMER EMAIL ERROR:", e)

        flash("Message sent successfully.", "success")
        return redirect(url_for("contact.contact"))

    return render_template("contact.html")