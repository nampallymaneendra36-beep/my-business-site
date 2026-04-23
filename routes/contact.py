from flask import Blueprint, render_template, request, flash, redirect, url_for
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
        message = request.form.get("message", "").strip()

        if not name or not email or not subject or not message:
            flash("All fields are required.", "error")
            return render_template("contact.html")

        new_message = ContactMessage(
            name=name,
            email=email,
            subject=subject,
            message=message
        )

        db.session.add(new_message)
        db.session.commit()

        admin_email_ok = False
        customer_email_ok = False

        try:
            admin_mail = Message(
                subject=f"New Contact Form: {subject}",
                sender="pureprosperitycyber@gmail.com",
                recipients=["pureprosperitycyber@gmail.com"],
                reply_to=email,
                body=f"""New contact message received.

Name: {name}
Email: {email}
Subject: {subject}

Message:
{message}
"""
            )
            mail.send(admin_mail)
            admin_email_ok = True
            print("ADMIN EMAIL SENT SUCCESSFULLY")
        except Exception as e:
            print("ADMIN EMAIL ERROR:", str(e))

        try:
            customer_mail = Message(
                subject="We received your message | Pure Prosperity Cyber",
                sender="pureprosperitycyber@gmail.com",
                recipients=[email],
                body=f"""Hi {name},

Thank you for contacting Pure Prosperity Cyber.

We have received your message regarding:
"{subject}"

Our team will review your request and get back to you as soon as possible.

Best regards,
Pure Prosperity Cyber
pureprosperitycyber@gmail.com
"""
            )
            mail.send(customer_mail)
            customer_email_ok = True
            print("CUSTOMER EMAIL SENT SUCCESSFULLY")
        except Exception as e:
            print("CUSTOMER EMAIL ERROR:", str(e))

        if admin_email_ok and customer_email_ok:
            flash("Message sent successfully! Confirmation email also sent.", "success")
        elif admin_email_ok and not customer_email_ok:
            flash("Message saved and admin email sent, but customer confirmation email failed.", "error")
        elif not admin_email_ok and customer_email_ok:
            flash("Message saved and customer confirmation email sent, but admin email failed.", "error")
        else:
            flash("Message saved, but both emails failed.", "error")

        return redirect(url_for("contact.contact"))

    return render_template("contact.html")