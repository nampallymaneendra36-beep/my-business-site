def analyze_lead(subject, message):
    text = f"{subject} {message}".lower()

    high_keywords = [
        "hacked", "breach", "data leak", "ransomware", "malware",
        "unauthorized access", "attack", "compromised"
    ]

    medium_keywords = [
        "vulnerability", "bug", "security issue",
        "login issue", "xss", "sql injection"
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

    if "hacked" in text or "breach" in text:
        category = "Incident Response"
    elif "vapt" in text or "testing" in text:
        category = "VAPT"
    else:
        category = "General Inquiry"

    return {
        "priority": priority,
        "category": category,
        "action": action
    }