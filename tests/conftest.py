# conftest.py
import pytest
import os
import tempfile
from app import app as flask_app
from db import db  # <-- IMPORTANT: use the same db object as models.py

@pytest.fixture
def app():
    """Create and configure a new app instance for each test."""
    db_fd, db_path = tempfile.mkstemp()

    flask_app.config.update({
        "TESTING": True,
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_path}",
        "SECRET_KEY": "test-secret-key",
        "WTF_CSRF_ENABLED": False,
    })

    with flask_app.app_context():
        db.create_all()

    yield flask_app

    # teardown
    with flask_app.app_context():
        db.session.remove()
        db.drop_all()
    os.close(db_fd)
    os.unlink(db_path)

@pytest.fixture
def db_session(app):
    """Provide a clean SQLAlchemy session in an app context."""
    with app.app_context():
        yield db.session
        db.session.rollback()

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def runner(app):
    return app.test_cli_runner()
