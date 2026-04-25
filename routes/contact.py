from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from flask_login import current_user
from flask_mail import Message
from extensions import db, mail
from models import ContactMessage
from utils.ai_agent import analyze_lead

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

        email_user = current_app.config.get("MAIL_USERNAME")

        if email_user:
            try:
                admin_msg = Message(
                    subject=f"New Lead [{ai['priority']}]: {subject}",
                    recipients=[email_user],
                    reply_to=email
                )

                admin_msg.body = f"""
New Lead Received

Name: {name}
Email: {email}
Subject: {subject}

Message:
{message_text}

AI Analysis:
Priority: {ai["priority"]}
Category: {ai["category"]}
Action: {ai["action"]}

Dashboard:
https://my-business-site-1gei.onrender.com/dashboard
"""
                mail.send(admin_msg)
                print("ADMIN EMAIL SENT")

            except Exception as e:
                print("ADMIN EMAIL ERROR:", str(e))

            try:
                customer_msg = Message(
                    subject="We received your request | Pure Prosperity Cyber",
                    recipients=[email]
                )

                customer_msg.body = f"""
Hi {name},

Thank you for contacting Pure Prosperity Cyber.

We received your request regarding:
{subject}

Our team will review it and get back to you soon.

Best regards,
Pure Prosperity Cyber
"""
                mail.send(customer_msg)
                print("CUSTOMER EMAIL SENT")

            except Exception as e:
                print("CUSTOMER EMAIL ERROR:", str(e))
        else:
            print("EMAIL NOT SENT: EMAIL_USER missing in Render Environment")

        flash("Message sent successfully.", "success")
        return redirect(url_for("contact.contact"))

    return render_template("contact.html")