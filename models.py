from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import secrets

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    shares = db.relationship('Share', backref='owner', lazy=True)
    collections = db.relationship('ShareCollection', backref='owner', lazy=True)

class Share(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_name = db.Column(db.String(255), nullable=False)
    mime_type = db.Column(db.String(255), nullable=True)
    upload_time = db.Column(db.DateTime, default=datetime.utcnow)
    expiry_time = db.Column(db.DateTime, nullable=False)
    download_count = db.Column(db.Integer, default=0)
    public_url = db.Column(db.String(512), nullable=False)
    
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    version = db.Column(db.Integer, nullable=False, default=2)
    
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
    sender_alias = db.Column(db.String(255), nullable=True)

class Setting(db.Model):
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.String(255), nullable=False)

class UserSetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    key = db.Column(db.String(50), nullable=False)
    value = db.Column(db.String(255), nullable=False)
    __table_args__ = (db.UniqueConstraint('user_id', 'key', name='uq_user_setting'),)

class LoginAttempt(db.Model):
    ip = db.Column(db.String(45), primary_key=True)
    attempts = db.Column(db.Integer, default=0)
    last_attempt = db.Column(db.DateTime, default=datetime.utcnow)

class RegistrationAttempt(db.Model):
    ip = db.Column(db.String(45), primary_key=True)
    attempts = db.Column(db.Integer, default=0)
    last_attempt = db.Column(db.DateTime, default=datetime.utcnow)

class ShareCollection(db.Model):
    __tablename__ = 'share_collection'
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expiry_time = db.Column(db.DateTime, nullable=False, index=True)
    download_count = db.Column(db.Integer, default=0, nullable=False)
    is_revoked = db.Column(db.Boolean, default=False, nullable=False, index=True)
    is_finalized = db.Column(db.Boolean, default=False, nullable=False)
    total_size = db.Column(db.BigInteger, default=0, nullable=False)
    file_count = db.Column(db.Integer, default=0, nullable=False)
    public_url = db.Column(db.String(512), nullable=False)

    # Relationships
    files = db.relationship('CollectionFile', backref='collection', lazy='joined', cascade="all, delete-orphan")
    transfers = db.relationship('CollectionTransfer', backref='collection', lazy=True, cascade="all, delete-orphan")
    download_tokens = db.relationship('CollectionDownloadToken', backref='collection', lazy=True, cascade="all, delete-orphan")

class CollectionFile(db.Model):
    __tablename__ = 'collection_file'
    id = db.Column(db.Integer, primary_key=True)
    collection_id = db.Column(db.Integer, db.ForeignKey('share_collection.id', ondelete='CASCADE'), nullable=False, index=True)
    file_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    stored_filename = db.Column(db.String(255), nullable=False)
    original_name = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.BigInteger, default=0, nullable=False)
    mime_type = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

class CollectionTransfer(db.Model):
    __tablename__ = 'collection_transfer'
    id = db.Column(db.Integer, primary_key=True)
    collection_id = db.Column(db.Integer, db.ForeignKey('share_collection.id', ondelete='CASCADE'), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

class CollectionDownloadToken(db.Model):
    __tablename__ = 'collection_download_token'
    id = db.Column(db.Integer, primary_key=True)
    collection_id = db.Column(db.Integer, db.ForeignKey('share_collection.id', ondelete='CASCADE'), nullable=False, index=True)
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    is_used = db.Column(db.Boolean, default=False, nullable=False, index=True)
