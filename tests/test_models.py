import pytest
from datetime import datetime
from sqlalchemy.exc import IntegrityError
from app import create_app
from models import db, User, Book, EbookLink, Session, Feedback

@pytest.fixture(scope='module')
def test_app():
    """Create and configure a test Flask app"""
    app = create_app({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'SQLALCHEMY_TRACK_MODIFICATIONS': False,
        'WTF_CSRF_ENABLED': False
    })
    
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()

@pytest.fixture(scope='function')
def test_client(test_app):
    """Create a test client"""
    return test_app.test_client()

@pytest.fixture(scope='function')
def init_database(test_app):
    """Initialize the database for each test"""
    with test_app.app_context():
        db.create_all()
        yield db
        db.session.remove()
        db.drop_all()

def test_user_creation(init_database):
    """Test User model creation and relationships"""
    # Create a test user
    user = User(
        username='testuser',
        email='test@example.com',
        password='password123'
    )
    
    db.session.add(user)
    db.session.commit()
    
    # Test user attributes
    assert user.id is not None
    assert user.username == 'testuser'
    assert user.email == 'test@example.com'
    assert user.password == 'password123'
    assert user.created_at is not None
    assert isinstance(user.created_at, datetime)
    
    # Test get_id method
    assert user.get_id() == str(user.id)
    
    # Test __repr__ method
    assert repr(user) == f"<User {user.username}>"

def test_user_required_fields(init_database):
    """Test User model required fields validation"""
    # Test missing username
    user1 = User(email='test@example.com', password='password123')
    db.session.add(user1)
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()
    
    # Test missing email
    user2 = User(username='testuser', password='password123')
    db.session.add(user2)
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()
    
    # Test missing password
    user3 = User(username='testuser', email='test@example.com')
    db.session.add(user3)
    with pytest.raises(IntegrityError):
        db.session.commit()

def test_book_creation(init_database):
    """Test Book model creation and relationships"""
    # Create a user first
    user = User(username='bookuser', email='book@example.com', password='password123')
    db.session.add(user)
    db.session.commit()
    
    # Create a book
    book = Book(
        title='Test Book',
        author='Test Author',
        description='A test book description',
        genre='Fiction',
        cover_url='http://example.com/cover.jpg',
        file_path='/path/to/file',
        file_type='pdf',
        user_id=user.id
    )
    
    db.session.add(book)
    db.session.commit()
    
    # Test book attributes
    assert book.id is not None
    assert book.title == 'Test Book'
    assert book.author == 'Test Author'
    assert book.description == 'A test book description'
    assert book.genre == 'Fiction'
    assert book.cover_url == 'http://example.com/cover.jpg'
    assert book.file_path == '/path/to/file'
    assert book.file_type == 'pdf'
    assert book.user_id == user.id
    
    # Test relationship
    assert book.user == user
    assert book in user.books
    
    # Test __repr__ method
    assert repr(book) == f'<Book {book.title}>'

def test_book_required_fields(init_database):
    """Test Book model required fields validation"""
    user = User(username='testuser', email='test@example.com', password='password123')
    db.session.add(user)
    db.session.commit()
    
    # Test missing title
    book1 = Book(
        author='Test Author',
        description='Test description',
        genre='Fiction',
        file_path='/path/to/file',
        file_type='pdf',
        user_id=user.id
    )
    db.session.add(book1)
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()
    
    # Test missing author
    book2 = Book(
        title='Test Book',
        description='Test description',
        genre='Fiction',
        file_path='/path/to/file',
        file_type='pdf',
        user_id=user.id
    )
    db.session.add(book2)
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()
    
    # Test missing file_path
    book3 = Book(
        title='Test Book',
        author='Test Author',
        description='Test description',
        genre='Fiction',
        file_type='pdf',
        user_id=user.id
    )
    db.session.add(book3)
    with pytest.raises(IntegrityError):
        db.session.commit()

def test_ebook_link_creation(init_database):
    """Test EbookLink model creation and relationships"""
    # Create user and book first
    user = User(username='ebookuser', email='ebook@example.com', password='password123')
    db.session.add(user)
    db.session.commit()
    
    book = Book(
        title='Ebook Test',
        author='Ebook Author',
        description='Ebook description',
        genre='Non-Fiction',
        file_path='/path/to/ebook',
        file_type='epub',
        user_id=user.id
    )
    db.session.add(book)
    db.session.commit()
    
    # Create ebook link
    ebook_link = EbookLink(
        title='Download Links',
        epub_link='http://example.com/book.epub',
        pdf_link='http://example.com/book.pdf',
        book_id=book.id
    )
    
    db.session.add(ebook_link)
    db.session.commit()
    
    # Test ebook link attributes
    assert ebook_link.id is not None
    assert ebook_link.title == 'Download Links'
    assert ebook_link.epub_link == 'http://example.com/book.epub'
    assert ebook_link.pdf_link == 'http://example.com/book.pdf'
    assert ebook_link.book_id == book.id
    
    # Test relationship
    assert ebook_link.book == book
    assert ebook_link in book.ebook_links
    
    # Test __repr__ method
    assert repr(ebook_link) == f'<EbookLink {ebook_link.title}>'

def test_ebook_link_cascade_delete(init_database):
    """Test that ebook links are deleted when book is deleted"""
    user = User(username='testuser', email='test@example.com', password='password123')
    db.session.add(user)
    db.session.commit()
    
    book = Book(
        title='Test Book',
        author='Test Author',
        description='Test description',
        genre='Fiction',
        file_path='/path/to/file',
        file_type='pdf',
        user_id=user.id
    )
    db.session.add(book)
    db.session.commit()
    
    ebook_link = EbookLink(
        title='Test Link',
        epub_link='http://example.com/test.epub',
        book_id=book.id
    )
    db.session.add(ebook_link)
    db.session.commit()
    
    # Verify link exists
    assert EbookLink.query.count() == 1
    
    # Delete book
    db.session.delete(book)
    db.session.commit()
    
    # Verify ebook link was cascade deleted
    assert EbookLink.query.count() == 0

def test_feedback_creation(init_database):
    """Test Feedback model creation and relationships"""
    # Create user first
    user = User(username='feedbackuser', email='feedback@example.com', password='password123')
    db.session.add(user)
    db.session.commit()
    
    # Create feedback
    feedback = Feedback(
        user_id=user.id,
        title='Test Feedback',
        content='This is a test feedback content'
    )
    
    db.session.add(feedback)
    db.session.commit()
    
    # Test feedback attributes
    assert feedback.id is not None
    assert feedback.user_id == user.id
    assert feedback.title == 'Test Feedback'
    assert feedback.content == 'This is a test feedback content'
    assert feedback.created_at is not None
    assert isinstance(feedback.created_at, datetime)
    
    # Test relationship
    assert feedback.user == user
    assert feedback in user.feedback
    
    # Test __repr__ method
    assert repr(feedback) == f'<Feedback {feedback.title}>'

def test_feedback_optional_title(init_database):
    """Test that Feedback title is optional"""
    user = User(username='testuser', email='test@example.com', password='password123')
    db.session.add(user)
    db.session.commit()
    
    feedback = Feedback(
        user_id=user.id,
        content='Feedback without title'
    )
    
    db.session.add(feedback)
    db.session.commit()
    
    assert feedback.id is not None
    assert feedback.title is None
    assert feedback.content == 'Feedback without title'

def test_session_creation(init_database):
    """Test Session model creation"""
    session = Session()
    
    db.session.add(session)
    db.session.commit()
    
    # Test session attributes
    assert session.id is not None
    assert session.timestamp is not None
    assert isinstance(session.timestamp, datetime)

def test_user_books_relationship(init_database):
    """Test User-Book relationship"""
    user = User(username='relationuser', email='relation@example.com', password='password123')
    db.session.add(user)
    db.session.commit()
    
    # Create multiple books for the user
    book1 = Book(
        title='Book 1',
        author='Author 1',
        description='Description 1',
        genre='Genre 1',
        file_path='/path/to/file1',
        file_type='pdf',
        user_id=user.id
    )
    
    book2 = Book(
        title='Book 2',
        author='Author 2',
        description='Description 2',
        genre='Genre 2',
        file_path='/path/to/file2',
        file_type='epub',
        user_id=user.id
    )
    
    db.session.add_all([book1, book2])
    db.session.commit()
    
    # Test relationship
    assert len(user.books) == 2
    assert book1 in user.books
    assert book2 in user.books
    assert book1.user == user
    assert book2.user == user

def test_user_feedback_relationship(init_database):
    """Test User-Feedback relationship"""
    user = User(username='feedbackuser', email='feedback@example.com', password='password123')
    db.session.add(user)
    db.session.commit()
    
    # Create multiple feedback entries
    feedback1 = Feedback(
        user_id=user.id,
        title='Feedback 1',
        content='Content 1'
    )
    
    feedback2 = Feedback(
        user_id=user.id,
        title='Feedback 2',
        content='Content 2'
    )
    
    db.session.add_all([feedback1, feedback2])
    db.session.commit()
    
    # Test relationship
    assert len(user.feedback) == 2
    assert feedback1 in user.feedback
    assert feedback2 in user.feedback
    assert feedback1.user == user
    assert feedback2.user == user

if __name__ == '__main__':
    pytest.main([__file__, '-v'])