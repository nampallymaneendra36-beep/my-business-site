from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from flask_login import current_user
from flask_mail import Message

from extensions import db, mail
from models import ContactMessage
from utils.ai_agent import analyze_lead


contact_bp = Blueprint("contact", __name__)


def build_customer_reply(name, subject, ai_result):
    priority = ai_result["priority"]

    if priority == "High":
        return f"""
Hi {name},

Thank you for contacting Pure Prosperity Cyber.

We received your urgent security request:

Subject: {subject}

Our team has marked this as HIGH priority. Please avoid making unnecessary changes to affected systems until reviewed.

Recommended immediate steps:
1. Do not delete logs.
2. Change passwords from a safe device.
3. Disconnect affected systems if active compromise is suspected.
4. Keep screenshots or evidence available.

Our team will review this and respond as soon as possible.

Best regards,
Pure Prosperity Cyber
"""

    if priority == "Medium":
        return f"""
Hi {name},

Thank you for contacting Pure Prosperity Cyber.

We received your security assessment request:

Subject: {subject}

Our team has categorized this as a security assessment request. We will review the details and help you plan the next steps.

Best regards,
Pure Prosperity Cyber
"""

    return f"""
Hi {name},

Thank you for contacting Pure Prosperity Cyber.

We received your request:

Subject: {subject}

Our team will review it and get back to you soon.

Best regards,
Pure Prosperity Cyber
"""


@contact_bp.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        subject = request.form.get("subject", "").strip()
        message_text = request.form.get("message", "").strip()

        if not name or not email or not subject or not message_text:
            flash("All fields are required.")
            return redirect(url_for("contact.contact"))

        ai_result = analyze_lead(subject, message_text)

        new_message = ContactMessage(
            name=name,
            email=email,
            subject=subject,
            message=message_text,
            status="New",
            is_read=False,
            user_id=current_user.id if current_user.is_authenticated else None,
            ai_priority=ai_result["priority"],
            ai_category=ai_result["category"],
            ai_action=ai_result["action"]
        )

        db.session.add(new_message)
        db.session.commit()

        admin_email = current_app.config.get("MAIL_USERNAME")

        if admin_email:
            try:
                admin_msg = Message(
                    subject=f"[{ai_result['priority']}] New Contact Request: {subject}",
                    recipients=[admin_email],
                    reply_to=email
                )

                admin_msg.body = f"""
New contact request received.

Name: {name}
Email: {email}
Subject: {subject}

Message:
{message_text}

AI Analysis:
Priority: {ai_result["priority"]}
Category: {ai_result["category"]}
Action: {ai_result["action"]}
"""

                mail.send(admin_msg)
                print("ADMIN EMAIL SENT SUCCESSFULLY")

            except Exception as e:
                print("ADMIN EMAIL ERROR:", str(e))

            try:
                customer_body = build_customer_reply(name, subject, ai_result)

                customer_msg = Message(
                    subject=f"We received your request | {ai_result['priority']} Priority",
                    recipients=[email]
                )

                customer_msg.body = customer_body

                mail.send(customer_msg)
                print("CUSTOMER EMAIL SENT SUCCESSFULLY")

            except Exception as e:
                print("CUSTOMER EMAIL ERROR:", str(e))
        else:
            print("EMAIL NOT SENT: MAIL_USERNAME missing in config or .env")

        flash("Message sent successfully.")
        return redirect(url_for("contact.contact"))

    return render_template("contact.html")