from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import secrets

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    shares = db.relationship('Share', backref='owner', lazy=True)

class Share(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_name = db.Column(db.String(255), nullable=False)
    upload_time = db.Column(db.DateTime, default=datetime.utcnow)
    expiry_time = db.Column(db.DateTime, nullable=False)
    download_count = db.Column(db.Integer, default=0)
    public_url = db.Column(db.String(512), nullable=False)
    
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    # Relationships
    transfers = db.relationship('Transfer', backref='share', lazy=True, cascade="all, delete-orphan")

class Transfer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    share_id = db.Column(db.Integer, db.ForeignKey('share.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Cipher(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    public_id = db.Column(db.String(32), unique=True, nullable=False)
    burn_on_read = db.Column(db.Boolean, default=True)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Setting(db.Model):
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.String(255), nullable=False)

class LoginAttempt(db.Model):
    ip = db.Column(db.String(45), primary_key=True)
    attempts = db.Column(db.Integer, default=0)
    last_attempt = db.Column(db.DateTime, default=datetime.utcnow)

class RegistrationAttempt(db.Model):
    ip = db.Column(db.String(45), primary_key=True)
    attempts = db.Column(db.Integer, default=0)
    last_attempt = db.Column(db.DateTime, default=datetime.utcnow)
