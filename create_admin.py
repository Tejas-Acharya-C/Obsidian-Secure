import os
import getpass
from werkzeug.security import generate_password_hash
from app import app, db
from models import User

def create_admin():
    with app.app_context():
        # Prompt for admin username
        username = input("Enter admin username [admin]: ").strip() or "admin"
        
        # Check if the user already exists
        existing_admin = User.query.filter_by(username=username).first()
        if existing_admin:
            print(f"Admin user '{username}' already exists.")
            return

        print(f"Creating admin user '{username}'.")
        
        # Prompt for password without echoing
        password = getpass.getpass(prompt='Enter password for admin: ')
        confirm_password = getpass.getpass(prompt='Confirm password: ')

        if password != confirm_password:
            print("Passwords do not match. Aborting.")
            return

        if len(password) < 8:
            print("Password must be at least 8 characters long.")
            return

        # Hash password and create user
        password_hash = generate_password_hash(password)
        new_admin = User(
            username=username,
            password_hash=password_hash,
            is_admin=True
        )
        
        db.session.add(new_admin)
        db.session.commit()
        
        print(f"Admin user '{username}' created successfully.")

if __name__ == '__main__':
    create_admin()
