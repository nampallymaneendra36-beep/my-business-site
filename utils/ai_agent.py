def analyze_lead(subject, message):
    subject = subject or ""
    message = message or ""

    text = f"{subject} {message}".lower()

    high_keywords = [
        "hacked", "breach", "data leak", "ransomware", "malware",
        "unauthorized access", "attack", "compromised", "urgent"
    ]

    medium_keywords = [
        "vulnerability", "bug", "security issue",
        "login issue", "xss", "sql injection", "phishing"
    ]

    if any(word in text for word in high_keywords):
        priority = "High"
        action = "Contact immediately"
    elif any(word in text for word in medium_keywords):
        priority = "Medium"
        action = "Respond within 24 hours"
    else:
        priority = "Low"
        action = "Normal follow-up"

    if "hacked" in text or "breach" in text or "compromised" in text:
        category = "Incident Response"
    elif "vapt" in text or "testing" in text or "vulnerability" in text:
        category = "VAPT / Web Security Testing"
    else:
        category = "General Inquiry"

    return {
        "priority": priority,
        "category": category,
        "action": action
    }