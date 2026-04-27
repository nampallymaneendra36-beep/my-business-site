from flask_mail import Message
from extensions import mail


def send_attack_alert(ip, attack_type, payload):
    try:
        msg = Message(
            subject=f"🚨 Attack Detected: {attack_type}",
            recipients=["pureprosperitycyber@gmail.com"],
            body=f"""
🚨 SECURITY ALERT 🚨

Attack Type: {attack_type}
IP Address: {ip}

Payload:
{payload}

-- Pure Prosperity Cyber SOC --
"""
        )

        mail.send(msg)
        print("✅ ALERT EMAIL SENT SUCCESSFULLY")

    except Exception as e:
        print("❌ EMAIL ERROR:", e)