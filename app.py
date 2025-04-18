from flask import Flask, render_template, redirect, session, request, flash, url_for, jsonify
import requests
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from .forms import UserForm, LoginForm, AddBookForm, EditBookForm
from flask_session import Session
from flask_wtf.csrf import generate_csrf
from datetime import timedelta
from .db import db  # Import db from the db.py file
from .models import User, Book, Session, db, connect_db 

# Initialize the migration extension
migrate = Migrate()

def create_app():
    app = Flask(__name__)
    
    # Flask app configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///books.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.secret_key = 'supersecretkey'
    app.config["SESSION_TYPE"] = "filesystem"  # Store sessions in a file
    app.config["SESSION_PERMANENT"] = True
    # Session(app)
    app.permanent_session_lifetime = timedelta(days=1)  # Sessions will last 1 day.
    
    # Initialize the database and migration extensions with the app
    db.init_app(app)  # Initialize db with app
    migrate.init_app(app, db)

    # Create the tables if they don't exist yet
    with app.app_context():
        db.create_all()

    return app

app = create_app() 

# API CALL

def fetch_books_from_api():
    api_url = "https://gutendex.com/books"
    response = requests.get(api_url)
    print(response.json())
    if response.status_code == 200:
        return response.json()
    else:
        return None

books = fetch_books_from_api()

def get_ebook_links(books):
    ebook_links = []

    for book in books['results']:
        print(f"Book data: {book}")

        if 'formats' in book:
            print(f"Formats available: {book['formats']}")    


            if 'application/epub+zip' in book['formats']:
        #Extract the EPUB download link
                epub_link = book['formats']['application/epub+zip']

                print(f"Found EPUB Link: {epub_link}")
                


                ebook_links.append({
                'title': book['title'],
                'author': book['authors'][0]['name'] if 'authors' in book and len(book['authors']) > 0 else 'Unknown',
                'epub_link': epub_link
                })
            else:
                print("No epub links found.")
        else:
            print("No format keys found in the book data.")

    return ebook_links

ebook_links = get_ebook_links(books)

for ebook in ebook_links:
    print(f"Title: {ebook['title']} | EPUB Link: {ebook['epub_link']}")

# HOME PAGE?

@app.route('/')
def home():
    return redirect('/login')

# LOGIN ROUTES

@app.route('/register', methods=['GET'])
def register():
    form = UserForm() #Create the instance for the UserForm
    return render_template("register_form.html", form=form)

@app.route('/register', methods=['POST'])
def process_register():
    form = UserForm(request.form)
    if form.validate_on_submit():
        print("Form validated successfully!")
        hashed_password = generate_password_hash(form.password.data)  # This hashes the password

        new_user = User(
            username=form.username.data,
            password=hashed_password,  # Save the hashed password
            email=form.email.data,
        )

        db.session.add(new_user)
        db.session.commit()
        print("User created successfully!")

        return redirect("/login")
    else:
        print(f"Form errors: {form.errors}")  # Print form validation errors for debugging
        return render_template("register_form.html", form=form)

@app.route('/login', methods=['GET'])
def login():
    form = LoginForm() #Create the instance for the Login Form
    return render_template("login_form.html", form=form)

@app.route('/login', methods=['POST'])
def process_login():
    form = LoginForm()
    print(f"Entered username: {form.username.data}")
    print(f"Entered password: {form.password.data}")

    if form.validate_on_submit():
        # Make sure the current app is the one initialized with the db instance
        user = User.query.filter_by(username=form.username.data).first()

        if user and check_password_hash(user.password, form.password.data):
            print(f"Stored hash: {user.password}") 
            session.permanent = True
            session['user_id'] = user.id  # Store user_id in session after login
            session['username'] = user.username
            print(f"User {user.username} logged in successfully.")
            return redirect(url_for('books_list', username=user.username))  # Redirect to user page after login
        else:
            print("Invalid username or password")
            return redirect("/login")  # Redirect back to login if invalid credentials
    else:
        print("Form validation failed")
        return render_template("login_form.html", form=form)  # Render login form if not submitted


@app.route('/secret', methods=['GET'])
def secret():
    # Check if the user is logged in by checking session for a username
    print(f"Session: {session}")
    if 'user_id' not in session:
        print("Redirecting: user_id is missing in session")
        return redirect('/login')  # If not logged in, redirect to login page
    print("User is authenticated, rendering secret page")
    return render_template("secret.html")  # Show the secret page

@app.route('/logout')
def logout():
    session.pop('username', None)  # Pop removes the username from session
    return redirect('/')  # Redirect to homepage

@app.route('/users/<username>')
def user_profile(username):
    # Check if user is logged in
    if 'user_id' not in session:
        return redirect('/login')

    # Get the current logged-in user's details
    user = User.query.filter_by(id=session['user_id']).first()

    # Check if the logged-in user matches the username from the URL
    if user.username != username:
        return redirect('/login')

    # Query the feedback from the current user by user_id (NOT by username)
    feedback_list = Feedback.query.filter_by(user_id=user.id).all()

    return render_template('user_profile.html', user=user, feedback_list=feedback_list)


    
@app.route('/users/<username>/delete', methods=['POST'])
def delete_user(username):
    # Ensure that the logged-in user is the one attempting to delete the user
    if 'username' not in session or session['username'] != username:
        return redirect('/login') # Redirect to login page
    
    user = User.query.filter_by(username=username).first()
    if not user or user.id != session ["user_id"]:
        flash("You are not authorized to delete this account.", "danger")
        return redirect("/")
    
    # Delete feedback
    Feedback.query.filter_by(user_id=user.id).delete()

    # Delete the user
    db.session.delete(user)
    db.session.commit()

    session.clear() # Log the user out
    flash("Account successfully deleted.", "success")
    return redirect("/")





# BOOKS ROUTES

@app.route('/books')
def books_list():
    books_data = fetch_books_from_api()  # Fetch the books data from the API
    ebooks_data = get_ebook_links(books_data)

    print("Books Data:", books_data)  # Check the entire books data
    print("Ebook Links:", ebooks_data)
    
    if books_data and 'results' in books_data:
        # Render the template with both books and ebooks_data (EPUB links)
        return render_template('books_list.html', books=books_data['results'], ebook_links=ebooks_data)
    else:
        print("No books data available or API request failed.")
        
        # Render the template with empty data if the request failed
        return render_template('books_list.html', books=[], ebook_links=[])



# @app.route('/books')
# def books_list():
#     """Populate Books from from Local Database and Fetch Books from API."""
#     books = Book.query.all()  # Get all books from the local database
#     book_data = fetch_books_from_api()
#       # Check if the data was fetched successfully
#     if not book_data:
#         return "No books found or failed to fetch from API.", 500

#     # Now we can loop through book_data
#     for book in book_data:
#         print(book)  # For debugging, remove after testing


    # if not books:
    #     books_data = fetch_books_from_api()

    # if books_data:
    #     for book_data in book_data:
    #         new_book = Book(
    #             title=book_data['title'],
    #             author=book_data['author'],
    #             desccription=book_data['description'],
    #             cover_url=book_data['cover_url']
    #         )
    #         db.session.add(new_book) # Add each new book to the session
    #         db.session.commit # Commit to save each book

        # books = Book.query.all() # Fetch the books again after adding them to the database
    return render_template('books_list.html', books=books)


@app.route('/add', methods=['GET', 'POST'])
def add_book():
    form = AddBookForm()
    if form.validate_on_submit():
        title = form.title.data
        author = form.author.data
        cover_url = form.cover_url.data
        page_count = form.page_count.data
        description = form.description.data
        
        # Create a new pet instance
        new_book = Book(title=title, author=author, cover_url=cover_url, page_count=page_count, description=description)

        existing_book = Book.query.filter_by(title=title, author=author).first()
        if existing_book is None:

            # Add to session and commit
            db.session.add(new_book)
            db.session.commit()
        
        # Redirect to home or another page
        return redirect(url_for('home'))

    return render_template('add_book.html', form=form)


@app.route('/books/<int:book_id>', methods=['GET', 'POST'])
def edit_book(book_id):
    book = Book.query.get_or_404(book_id)
    form = EditBookForm(obj=book) #pre fill with the book data

    if form.validate_on_submit():
        book.cover_url = form.cover_url.data
        book.description = form.description.data
        book.available = form.available.data

 
        db.session.commit()
        return redirect(url_for('books_list'))
    
    return render_template('edit_book.html', book=book, form=form)


@app.route('/books/<int:book_id>/delete', methods=['POST'])
def delete_book(book_id):
    book = Book.query.get_or_404(book_id)
    db.session.delete(book)
    db.session.commit()
    return redirect(url_for('books_list'))

@app.context_processor
def csrf_token():
    return dict(csrf_token=generate_csrf)


if __name__ == "__main__":
    app.run(debug=True)