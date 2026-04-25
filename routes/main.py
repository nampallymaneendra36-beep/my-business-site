@main_bp.route("/admin-reset-password")
def admin_reset_password():
    from werkzeug.security import generate_password_hash
    from models import User
    from extensions import db

    token = request.args.get("token")

    if token != "ppc-reset-2026":
        return "Unauthorized", 403

    user = User.query.filter_by(email="nampallymaneendra36@gmail.com").first()

    if not user:
        return "User not found"

    user.password_hash = generate_password_hash("Admin@123")
    db.session.commit()

    return "Password reset successfully on server"