from flask import Flask, render_template, redirect, session, request, flash, url_for, jsonify, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from cryptography.fernet import Fernet
import requests
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from .forms import UserForm, LoginForm, AddBookForm, EditBookForm
from flask_session import Session
from flask_wtf.csrf import generate_csrf
from datetime import timedelta
from .db import db  # Import db from the db.py file
from .models import User, Book, EbookLink, Session, db, connect_db 

login_manager = LoginManager() # This needs to be defined
# Initialize the migration extension
migrate = Migrate()

# Generate a key for encryption
key = Fernet.generate_key()
fernet = Fernet(key)
# Print the key for debugging purposes
print(key)

def encrypt_file(file_path):
    with open(file_path, 'rb') as file:
        file_data = file.read()
    encrypted_data = fernet.encrypt(file_data)

    encrypted_file_path = file_path + '.enc' #Saving encrypted file with a different extension .enc
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data)

    return encrypted_file_path

def decrypt_file(encrypted_file_path):
    with open(encrypted_file_path, 'rb') as file:
        encrypted_data = file.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    
    decrypted_file_path = encrypted_file_path.replace(".enc", "")  # Remove the .enc extension
    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)
    
    return decrypted_file_path
         

def create_app():
    app = Flask(__name__)

 
    login_manager.init_app(app)
    login_manager.login_view = 'login'# Redirect to login page if user is not logged in
    
    # Flask app configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///books.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.secret_key = 'supersecretkey'
    app.config["SESSION_TYPE"] = "filesystem"  # Store sessions in a file
    app.config["SESSION_PERMANENT"] = True
    basedir = os.path.abspath(os.path.dirname(__file__))
    app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    # Create the folder if it doesn't exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 16MB limit
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

#ALLOWED EXTENSIONS

ALLOWED_EXTENSIONS = {'pdf', 'epub'}

#Check Allowed File Extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
#UPLOAD FOLDER
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)  # Create the upload folder if it doesn't exist

# API CALL

def fetch_books_from_api():
    api_url = "https://gutendex.com/books"
    response = requests.get(api_url)
    if response.status_code == 200:
        return response.json()
    else:
        return None
books = fetch_books_from_api()

def get_ebook_links(books):
    ebook_links = []
    for book in books['results']:
        if 'formats' in book:   
            if 'application/epub+zip' in book['formats']:
        #Extract the EPUB download link
                epub_link = book['formats']['application/epub+zip']
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

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=True)  # This ensures the user is logged in and stays logged in
            return redirect(url_for('books_list'))  # Redirect to the books list page after login
        else:
            flash('Invalid username or password')
    return render_template('login_form.html', form=form)

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
    logout_user()  # Pop removes the username from session
    return redirect('/login') 

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
@login_required 
def books_list():
    books_data = fetch_books_from_api()  # Fetch the books data from the API
    uploaded_books = Book.query.all()  # Get all books from the local database (uploaded books)
    ebooks_data = get_ebook_links(books_data) #Fetch the ebook data from the API

    # print("Books Data:", books_data)  # Check the entire books data
    # print("Ebook Links:", ebooks_data)
    
    if books_data and 'results' in books_data:
        # Render the template with both books and ebooks_data (EPUB links)
        return render_template('books_list.html', books=books_data['results'], uploaded_books=uploaded_books, ebook_links=ebooks_data)
    else:
        print("No books data available or API request failed.")
        
        # Render the template with empty data if the request failed
        return render_template('books_list.html', books=[], ebook_links=[])


# Ensure books route is defined and works
@app.route('/books')
@login_required 
def books():
    books_data = Book.query.all()
    return render_template('books_list.html', books=books_data)

@app.route('/add', methods=['GET', 'POST'])
@login_required 
def add_book():
    """Add a new book to the Book list."""
    if current_user.is_authenticated:
        print(f"User {current_user.username} is logged in.")
    else:
        print("No user is logged in.")

    print("adding a book started")
    form = AddBookForm()
    print("Form instance created")

    # Print form data for debugging
    if request.method == 'POST':
        print("POST request received")
        print(f"Form data: {request.form}")
        print(f"Files: {request.files}")
        print(f"Validate on submit: {form.validate_on_submit()}")
        print(f"Form errors: {form.errors}")

    if form.validate_on_submit():
        print("Form validated successfully")
        title = form.title.data
        author = form.author.data
        cover_url = form.cover_url.data
        genre = form.genre.data
        description = form.description.data
        file = form.file.data
        print(f"Received file: {file}")

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            # Encryption and saving the file
            encrypted_file_path = encrypt_file(file_path)
            print(f"File saved to: {file_path}")

            # Determine file type
            file_extension = os.path.splitext(filename)[1].lower()
            print(f"File extension: {file_extension}")

            # Set file_type based on the file extension
            file_type = 'pdf' if file_extension == '.pdf' else 'epub' if file_extension == '.epub' else None

            # Ensure file_type is set correctly
            if not file_type:
                flash('Invalid file type. Only PDF and EPUB files are allowed.')
                return redirect(url_for('add_book'))

            

            # Create a new book instance
            new_book = Book(
                title=title,
                author=author,
                cover_url=cover_url,
                genre=genre,
                description=description,
                file_path=encrypted_file_path,
                file_type=file_type, 
                user_id=current_user.id,
            )
            print(f"New book created: {new_book}")

            # Check if book already exists
            existing_book = Book.query.filter_by(title=title, author=author).first()
            if existing_book is None:
                db.session.add(new_book)
                db.session.commit()
                print(f"New book added to database: {new_book}")

                # Create ebook link entry
                new_ebook_link = EbookLink(
                    title=title,
                    epub_link=file_path if file_extension == '.epub' else None,
                    pdf_link=file_path if file_extension == '.pdf' else None,
                    book_id=new_book.id
                )

                db.session.add(new_ebook_link)
                db.session.commit()
                print(f"New ebook_link added to database: {new_ebook_link}")

                # Redirect to books page after successful form submission
                print("Redirecting to /books...")
                return redirect(url_for('books'))  # This will redirect to the /books route
            else:
                flash('This book already exists in the database.')
                print("Book already exists, not added.")
    
    return render_template('add_book.html', form=form)

@app.route('/uploads/<filename>')
@login_required 
def upload_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/books/<int:book_id>', methods=['GET', 'POST'])
@login_required 
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


@app.route('/delete_book/<int:book_id>', methods=['POST'])
@login_required 
def delete_book(book_id):
    book = Book.query.get_or_404(book_id)
    try:
        db.session.delete(book)  # Deletes the book from the database
        db.session.commit()       # Commit the changes to the database
        flash('Book deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting the book: {str(e)}', 'danger')
    return redirect(url_for('books_list'))  # Redirect to the books list page


@app.context_processor
def csrf_token():
    return dict(csrf_token=generate_csrf)


if __name__ == "__main__":
    app.run(debug=True)