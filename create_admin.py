from app import app, db, User  # Import the app, db, and User model
from werkzeug.security import generate_password_hash  # For password hashing

with app.app_context():
    # Check if the admin user already exists
    admin_user = User.query.filter_by(username='admin').first()

    if not admin_user:
        admin_user = User(username='admin', is_admin=True)
        admin_user.set_password('symphony')  # Securely hash the password
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created successfully!")
    else:
        print("Admin user already exists.")

