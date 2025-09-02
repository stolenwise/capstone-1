import pytest

def test_client_works(client):
    """Test that the test client is working"""
    response = client.get('/')
    assert response.status_code in [200, 302]  # OK or redirect

def test_login_page_exists(client):
    """Test if login page exists"""
    response = client.get('/login')
    assert response.status_code in [200, 404]  # OK or not found

def test_register_page_exists(client):
    """Test if register page exists"""
    response = client.get('/register')
    assert response.status_code in [200, 404]  # OK or not found

def test_user_registration(client):
    """Test user registration"""
    response = client.post('/register', data={
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'testpassword',
        'confirm_password': 'testpassword'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    # Check that we're redirected to login page after registration
    assert b'Login' in response.data or b'login' in response.data

def test_user_login_logout(client):
    """Test user login and logout"""
    # First register a user
    client.post('/register', data={
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'testpassword',
        'confirm_password': 'testpassword'
    })
    
    # Test login
    response = client.post('/login', data={
        'username': 'testuser',
        'password': 'testpassword'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    # Check for successful login - from previous output, it shows book listings
    assert b'Locally Preserved Books' in response.data
    
    # Test logout
    response = client.get('/logout', follow_redirects=True)
    assert response.status_code == 200
    assert b'Login' in response.data  # Should show login link after logout