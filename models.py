from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import UserMixin
from .db import db


# Define classes for User, Book, and Session
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    def get_id(self):
        return str(self.id)  # Return the ID as a string (Flask-Login needs it as a string)

    feedback = db.relationship('Feedback', backref='user', lazy=True)

    
    def __repr__(self):
        return f"<User {self.username}>"

class Book(db.Model):
    __tablename__ = 'books'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(1000), nullable=False)
    genre = db.Column(db.String(50), nullable=False)
    cover_url = db.Column(db.String(5000)) 
    file_path = db.Column(db.String(200), nullable=False)
    file_type = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    user = db.relationship('User', backref=db.backref('books', lazy=True))
    

    ebook_links = db.relationship('EbookLink', back_populates='book', cascade="all, delete-orphan")

    def __repr__(self):
        return f'<Book {self.title}>'

class EbookLink(db.Model):
    __tablename__ = 'ebook_links'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    epub_link = db.Column(db.String(255))
    pdf_link = db.Column(db.String(255))
    book_id = db.Column(db.Integer, db.ForeignKey('books.id'), nullable=False)  # Foreign key to Book table
    book = db.relationship('Book', back_populates='ebook_links')

    def __repr__(self):
        return f'<EbookLink {self.title}>'

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
