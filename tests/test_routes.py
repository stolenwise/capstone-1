import pytest
import os
import tempfile
import io
from unittest.mock import patch, MagicMock
from werkzeug.datastructures import FileStorage
from flask import session, url_for, get_flashed_messages

# Import the actual app instance and db
from app import app, db, encrypt_file, decrypt_file, allowed_file
from models import User, Book

@pytest.fixture
def client():
    """Create a test client using the actual app instance"""
    # Configure for testing
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SECRET_KEY'] = 'test-secret-key'
    
    # Create upload folder for testing
    with tempfile.TemporaryDirectory() as temp_dir:
        app.config['UPLOAD_FOLDER'] = temp_dir
        
        with app.app_context():
            db.create_all()
            yield app.test_client()
            db.drop_all()

@pytest.fixture
def init_database():
    """Initialize the database with test data"""
    with app.app_context():
        # Create test user
        user = User(
            username='testuser',
            email='test@example.com',
            password='pbkdf2:sha256:150000$TESTHASH$testhash123'
        )
        db.session.add(user)
        db.session.commit()
        
        # Create test book
        book = Book(
            title='Test Book',
            author='Test Author',
            description='Test Description',
            genre='Fiction',
            file_path='/test/path.enc',
            file_type='pdf',
            user_id=user.id
        )
        db.session.add(book)
        db.session.commit()
        
        yield
        
        db.session.rollback()

@pytest.fixture
def authenticated_client(client, init_database):
    """Create an authenticated test client by logging in through the form"""
    # First, create a user to log in with
    with app.app_context():
        user = User(
            username='authuser',
            email='auth@example.com',
            password='pbkdf2:sha256:150000$TESTHASH$authtesthash'
        )
        db.session.add(user)
        db.session.commit()
    
    # Mock the password check and log in
    with patch('app.check_password_hash', return_value=True):
        client.post('/login', data={
            'username': 'authuser',
            'password': 'testpassword'
        })
    
    return client

# 1. HOME ROUTE - Landing page (should work without auth)
def test_home_route(client):
    """Test home page is accessible"""
    response = client.get('/home')
    assert response.status_code == 200
    assert b'Home' in response.data

def test_index_redirects_to_home(client):
    """Test root URL redirects to home"""
    response = client.get('/')
    assert response.status_code == 302
    assert response.location.endswith('/home')

# 2. LOGIN ROUTE - Authentication
def test_login_get(client):
    """Test login page loads"""
    response = client.get('/login')
    assert response.status_code == 200
    assert b'Login' in response.data

def test_login_post_success(client):
    """Test successful login"""
    # Create a test user first
    with app.app_context():
        user = User(
            username='loginuser',
            email='login@example.com',
            password='pbkdf2:sha256:150000$TESTHASH$loginhash'
        )
        db.session.add(user)
        db.session.commit()
    
    # Mock password check since we can't easily recreate the same hash
    with patch('app.check_password_hash', return_value=True):
        response = client.post('/login', data={
            'username': 'loginuser',
            'password': 'testpassword'
        }, follow_redirects=True)
        
        # Should redirect to books list after successful login
        assert response.status_code == 200

# 3. REGISTER ROUTE - User creation
def test_register_get(client):
    """Test register page loads"""
    response = client.get('/register')
    assert response.status_code == 200
    assert b'Register' in response.data

def test_register_post_success(client):
    """Test successful registration"""
    response = client.post('/register', data={
        'username': 'newuser',
        'email': 'newuser@example.com',
        'password': 'password123',
        'confirm_password': 'password123'
    }, follow_redirects=True)
    
    # Should redirect to login after registration
    assert response.status_code == 200
    assert b'Login' in response.data

# 4. BOOKS LIST ROUTE - Main content (requires auth)
def test_books_list_requires_auth(client):
    """Test books list redirects to login when not authenticated"""
    response = client.get('/books')
    assert response.status_code == 302  # Redirect to login
    assert '/login' in response.location

@patch('app.fetch_books_from_api')
def test_books_list_authenticated(mock_fetch, authenticated_client):
    """Test books list works when authenticated"""
    mock_fetch.return_value = {
        'results': [{
            'title': 'Test Book',
            'authors': [{'name': 'Test Author'}],
            'formats': {
                'text/html': 'https://example.com/read.html',
                'application/epub+zip': 'https://example.com/book.epub',
                'application/pdf': 'https://example.com/book.pdf',
                'image/jpeg': 'https://example.com/cover.jpg'
            }
        }]
    }

    response = authenticated_client.get('/books')
    assert response.status_code == 200
    assert b'Test Book' in response.data

# 5. ADD BOOK ROUTE - Content creation (requires auth)
def test_add_book_requires_auth(client):
    """Test add book page requires authentication"""
    response = client.get('/add')
    assert response.status_code == 302  # Redirect to login
    assert '/login' in response.location

def test_add_book_get_authenticated(authenticated_client):
    """Test add book page loads when authenticated"""
    response = authenticated_client.get('/add')
    assert response.status_code == 200
    assert b'Add Book' in response.data

# 6. DOWNLOAD ROUTE - Core functionality (requires auth)
def test_download_requires_auth(client):
    """Test download requires authentication"""
    response = client.get('/download/1')
    assert response.status_code == 302  # Redirect to login
    assert '/login' in response.location

# 7. LOGOUT ROUTE - Session management
def test_logout(authenticated_client):
    """Test logout functionality"""
    response = authenticated_client.get('/logout', follow_redirects=True)
    assert response.status_code == 200
    # Should redirect to login after logout
    assert b'Login' in response.data

# 8. USER PROFILE ROUTE - User management (requires auth)
def test_user_profile_requires_auth(client):
    """Test user profile requires authentication"""
    response = client.get('/users/testuser')
    assert response.status_code == 302  # Redirect to login
    assert '/login' in response.location

# 9. SECRET ROUTE - Protected content (requires auth)
def test_secret_requires_auth(client):
    """Test secret page requires authentication"""
    response = client.get('/secret')
    assert response.status_code == 302  # Redirect to login
    assert '/login' in response.location

# 10. API ROUTES - Public endpoints
@patch('app.fetch_books_from_api')
def test_api_books(mock_fetch, client):
    """Test API books endpoint"""
    mock_fetch.return_value = {'results': []}
    response = client.get('/api/books')
    assert response.status_code == 200
    assert response.is_json

@patch('app.fetch_books_from_api')
def test_api_ebook_links(mock_fetch, client):
    """Test API ebook links endpoint"""
    mock_fetch.return_value = {'results': []}
    response = client.get('/api/ebook-links')
    assert response.status_code == 200
    assert response.is_json

# Utility function tests
def test_allowed_file():
    """Test file extension validation"""
    assert allowed_file('test.pdf') == True
    assert allowed_file('test.epub') == True
    assert allowed_file('test.txt') == False
    assert allowed_file('test') == False

# Test authentication decorator protection
def test_protected_routes_redirect_to_login(client):
    """Test that all protected routes redirect to login when not authenticated"""
    protected_routes = [
        '/books',
        '/add', 
        '/download/1',
        '/users/testuser',
        '/secret',
        '/users/testuser/edit'
    ]
    
    for route in protected_routes:
        response = client.get(route)
        assert response.status_code == 302, f"Route {route} should redirect to login"
        assert '/login' in response.location, f"Route {route} should redirect to login"

if __name__ == '__main__':
    pytest.main([__file__, '-v'])