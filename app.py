from flask import Flask, render_template, redirect, session, request, flash, url_for, jsonify, send_from_directory, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from cryptography.fernet import Fernet
import requests
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms.validators import EqualTo, Optional 
from werkzeug.utils import secure_filename
import os
from forms import UserForm, LoginForm, AddBookForm, EditBookForm, EditProfileForm
from flask_session import Session
from flask_wtf.csrf import generate_csrf
from datetime import timedelta
from db import db  # Import db from the db.py file
from models import User, Book, EbookLink, Session, db, connect_db 

login_manager = LoginManager() # This needs to be defined
# Initialize the migration extension
migrate = Migrate()

# Generate a key for encryption
KEY_FILE = 'encryption_key.key'

def get_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as key_file:
            key = key_file.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as key_file:
            key_file.write(key)
    return key

key = get_or_create_key()
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


def create_app(test_config=None):
    app = Flask(__name__, template_folder='templates', static_folder='static')
    
    # Default configuration
    app.config.from_mapping(
        SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', 'sqlite:///books.db').replace('postgres://', 'postgresql://'),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SECRET_KEY=os.environ.get('SECRET_KEY', 'dev-secret-key'),
        SESSION_TYPE="filesystem",
        UPLOAD_FOLDER=os.environ.get('UPLOAD_FOLDER', 'uploads'),
        MAX_CONTENT_LENGTH=500 * 1024 * 1024,
        WTF_CSRF_ENABLED=True,
        TESTING=False
    )
    
    
    # Override with test config if provided
    if test_config:
        app.config.update(test_config)
    else:
        # Load production config if it exists
        app.config.from_pyfile('config.py', silent=True)
    
    # Ensure upload folder exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.permanent_session_lifetime = timedelta(days=1)
    
    # Initialize extensions
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    db.init_app(app)
    migrate.init_app(app, db)
    
    # # Import and register blueprints (adjust based on your actual structure)
    # from .routes import main_bp, auth_bp  # Adjust these imports based on your actual structure
    
    # app.register_blueprint(main_bp)
    # app.register_blueprint(auth_bp)
    
    # Create tables if they don't exist
    with app.app_context():
        db.create_all()
    
    return app

# Create the application instance
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


@app.route('/api/books')
def api_books():
    books = fetch_books_from_api()
    return jsonify(books)


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

@app.route('/api/ebook-links')  
def api_ebook_links():
    books = fetch_books_from_api()
    ebook_links = get_ebook_links(books)
    return jsonify(ebook_links)

@app.route('/debug')
def debug():
    import os
    template_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
    template_files = []
    if os.path.exists(template_path):
        template_files = os.listdir(template_path)
    
    return f"""
    <h1>Debug Info</h1>
    <p>App is running!</p>
    <p>Current working directory: {os.getcwd()}</p>
    <p>Template path: {template_path}</p>
    <p>Template exists: {os.path.exists(template_path)}</p>
    <p>Template files: {template_files}</p>
    <p>All routes: {[rule.rule for rule in app.url_map.iter_rules()]}</p>
    """

@app.route('/debug/ebooks')
def debug_ebooks():
    books = fetch_books_from_api()
    ebook_links = get_ebook_links(books)
    for ebook in ebook_links:
        print(ebook['title'])  # This is now inside a function
    return "Check console for output"

@app.route('/static-test')
def static_test():
    return app.send_static_file('style.css') if hasattr(app, 'static_folder') else "No static folder"

# HOME PAGE


@app.route('/home')
def home():
    """Home landing page"""
    try:
        if current_user.is_authenticated:
            user_books = current_user.books
        else:
            user_books = []
        
        return render_template('home.html', user_books=user_books)
    except Exception as e:
        return f"Error: {str(e)}", 500

@app.route('/')
def index():
    """Redirect root URL to home page"""
    return redirect('/home') 



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



# LOGIN ROUTES

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = UserForm()
    
    if request.method == 'POST':
        if form.validate_on_submit():
            try:
                hashed_password = generate_password_hash(form.password.data)
                new_user = User(
                    username=form.username.data,
                    password=hashed_password,
                    email=form.email.data,
                )
                db.session.add(new_user)
                db.session.commit()
                flash('Registration successful! Please log in.')
                return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback()
                flash('Error creating account. Please try again.')
                print(f"Registration error: {str(e)}")
        else:
            print(f"Form errors: {form.errors}")
    
    return render_template("register_form.html", form=form)
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data if hasattr(form, 'remember') else True)
            flash('Logged in successfully!')
            
            # Set session as permanent
            session.permanent = True
            
            # Redirect to next page if it exists, otherwise to books_list
            next_page = request.args.get('next')
            return redirect(next_page or url_for('books_list'))
        else:
            flash('Invalid username or password')
    
    return render_template('login_form.html', form=form)

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
@login_required
def user_profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    return render_template('user_profile.html', user=user)

@app.route('/users/<username>/edit', methods=['GET', 'POST'])
@login_required
def edit_profile(username):
    # Ensure the logged-in user is editing their own profile
    if current_user.username != username:
        flash("You can only edit your own profile.", "danger")
        return redirect(url_for('user_profile', username=current_user.username))
    
    form = EditProfileForm()
    
    if form.validate_on_submit():
        try:
            # Verify current password first
            if not check_password_hash(current_user.password, form.current_password.data):
                flash("Current password is incorrect.", "danger")
                return render_template('edit_profile.html', form=form, user=current_user)
            
            # Update user data
            current_user.username = form.username.data
            current_user.email = form.email.data
            
            # Update password if provided
            if form.password.data:
                current_user.password = generate_password_hash(form.password.data)
                flash("Password updated successfully!", "success")
            
            db.session.commit()
            flash("Profile updated successfully!", "success")
            return redirect(url_for('user_profile', username=current_user.username))
        except Exception as e:
            db.session.rollback()
            flash("An error occurred while updating your profile.", "danger")
    
    # Pre-populate the form with current user data (except passwords)
    form.username.data = current_user.username
    form.email.data = current_user.email
    
    return render_template('edit_profile.html', form=form, user=current_user)
    
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

@app.route('/download/<int:book_id>')
@login_required
def download_book(book_id):
    book = Book.query.get_or_404(book_id)
    
    if not book.file_path:
        flash('No file available for this book', 'error')
        return redirect(url_for('books_list'))

    encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], 
                                     os.path.basename(book.file_path))
    
    if not os.path.exists(encrypted_file_path):
        flash('File not found on server', 'error')
        return redirect(url_for('books_list'))

    try:
        # Decrypt the file
        decrypted_file_path = decrypt_file(encrypted_file_path)
        
        # Get the original filename without .enc
        original_filename = os.path.basename(book.file_path).replace('.enc', '')
        
        # Send the decrypted file
        response = send_file(
            decrypted_file_path,
            as_attachment=True,
            download_name=original_filename
        )
        
        # Clean up the decrypted file after sending
        @response.call_on_close
        def cleanup():
            try:
                os.remove(decrypted_file_path)
            except Exception as e:
                app.logger.error(f"Error cleaning up decrypted file: {e}")
        
        return response
        
    except Exception as e:
        flash('Failed to decrypt file. Please contact support.', 'error')
        app.logger.error(f"Decryption failed for book {book_id}: {str(e)}")
        return redirect(url_for('books_list'))


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