from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from .db import db

# Define classes for User, Book, and Session
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    feedback = db.relationship('Feedback', backref='user', lazy=True)

    book = db.relationship('Book', backref='user', lazy=True)
    
    def __repr__(self):
        return f"<User {self.username}>"

class Book(db.Model):
    __tablename__ = 'books'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(1000), nullable=False)
    # file_path = local path to file
    # file_type = PDF/EPUB
    # uploaded_by = db.Column(db.User)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    # Add the user_id column here to reference the User model
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

class Session(db.Model):
    __tablename__ = 'sessions'
    id = db.Column(db.Integer, primary_key=True)
    # user_id = db.Column(db.User)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

class Feedback(db.Model):
    __tablename__ = 'feedback'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(100), nullable=True)  # Add title column
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    
    def __repr__(self):
        return f'<Feedback {self.title}>'

def connect_db(app):
    db.app = app
    db.init_app(app)
