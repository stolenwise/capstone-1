# capstone-1

### The Gnarly Book Garden (Digital Library)

A small Flask web app for collecting and serving your personal e-book library. Users can register, log in, upload books (stored on disk with optional encryption), browse the catalog, and download their files. JSON endpoints expose basic book/link data.

### Features

Auth: register, log in/out (session-based).

Books: upload PDF/EPUB with metadata; list & download.

Optional file encryption: uploaded files are stored encrypted; downloads decrypt on the fly.

Models: User, Book, EbookLink, Feedback, Session.

JSON APIs: /api/books, /api/ebook_links.

Tests: route & model coverage via pytest.

### Tech Stack

Python 3.13, Flask 3.x

SQLAlchemy 2.x + Flask-SQLAlchemy

Flask-Migrate (Alembic)

WTForms / Flask-WTF

Flask-Session (server-side session)

Gunicorn (production WSGI)

(Optional) Postgres in production (Render)

### Project Structure (top-level)
.
├── app.py                 # Flask app / routes (factory: create_app or create_test)
├── db.py                  # db = SQLAlchemy()
├── models.py              # User, Book, EbookLink, Feedback, Session
├── templates/             # Jinja templates (base.html, books_list.html, etc.)
├── static/                # static assets (optional)
├── encryption_key.key     # (generated) symmetric key for file encryption
├── requirements.txt
├── tests/
│   ├── conftest.py
│   ├── test_models.py
│   └── test_routes.py
└── README.md


If your app lives in a subfolder, adjust paths/commands accordingly.

Getting Started (Local)
1) Prereqs

Python 3.13+

pip + virtualenv

2) Setup
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

3) Environment

Create .env (or export vars in your shell):

# required
SECRET_KEY=change-me
SQLALCHEMY_DATABASE_URI=sqlite:///app.db
UPLOAD_FOLDER=./uploads

# optional
FLASK_ENV=development


For SQLite, the DB file is created on first run. For production, use Postgres (SQLALCHEMY_DATABASE_URI=$DATABASE_URL).

4) Database
# First time:
flask db init
flask db migrate -m "init"
flask db upgrade

5) Run (dev)

If you expose a factory:

# if factory is create_app()
export FLASK_APP="app:create_app()"
flask run


If you expose a module-level app:

export FLASK_APP=app.py
flask run

### Tests
pytest -q
# or verbose:
pytest -v


The suite covers:

Auth flows (login/register/logout)

Protected route redirects

Books list/add/download

JSON APIs

Models & relationships (incl. cascade delete on EbookLink)

### Routes (HTML)
Method	Path	                    Notes
GET	    /	                        Redirects to /home
GET	    /home	                    Landing page
GET	    /login	                    Login form
POST	/login	                    Authenticate, set session
GET	    /register	                Registration form
POST	/register	                Create user
GET	    /books	                    Auth required. List catalog
GET	    /add	                    Auth required. Show add form
POST	/add	                    Auth required. Upload & encrypt
GET	    /download/<int:book_id>	    Auth required. Decrypt & send file
GET	    /users/<username>	        Auth required. User profile
POST	/users/<username>/edit	    Auth required. Update profile
POST	/delete_book/<int:book_id>	Auth required. Delete book
GET	/logout	                        Clear session
GET	/secret	                        Auth required. Test-protected page

### JSON APIs
Method	Path	                    Returns
GET	    /api/books	                Books (normalized list)
GET	    /api/ebook_links	        Ebook link records


### File Encryption (overview)

Uploads go to UPLOAD_FOLDER.

Files are encrypted at rest (helpers encrypt_file / decrypt_file).

A symmetric key lives in encryption_key.key (create it securely on first run; keep it secret and out of VCS).

Downloads decrypt to a temp path and stream via send_file.

In tests, those helpers are patched; in production they must exist and be safe. Consider rotating keys and using a secrets manager.

### Deploying on Render

Create a Web Service (not Static Site).

Root Directory: leave blank (.) if your app is at repo root.

Runtime: Python

Build Command:

pip install -r requirements.txt


Start Command (pick one that matches your entrypoint):

# factory:
gunicorn --bind 0.0.0.0:$PORT "app:create_app()"
# or if factory is named create_test():
gunicorn --bind 0.0.0.0:$PORT "app:create_test()"
# or module-level app:
gunicorn --bind 0.0.0.0:$PORT app:app


Env Vars:

SECRET_KEY

SQLALCHEMY_DATABASE_URI=$DATABASE_URL (when using Render Postgres)

UPLOAD_FOLDER=/var/tmp/uploads (or another writable path)

Notes

Add gunicorn (and psycopg2-binary if using Postgres) to requirements.txt.

Don’t use “Static Site” for Flask; that requires a Publish Directory and won’t run Python.

If your code lives in a subfolder, set Root Directory to that folder.

Example render.yaml (optional):

services:
  - type: web
    name: book-garden
    runtime: python
    repo: https://github.com/yourname/capstone-1
    branch: main
    rootDir: .
    buildCommand: pip install -r requirements.txt
    startCommand: gunicorn --bind 0.0.0.0:$PORT "app:create_app()"
    envVars:
      - key: SECRET_KEY
        value: change-me
      # - key: SQLALCHEMY_DATABASE_URI
      #   fromDatabase:
      #     name: your-postgres
      #     property: connectionString


### Troubleshooting

404 on every route in tests: your app factory returned an app with no routes registered. Ensure blueprints/routes are imported & registered inside the factory before returning.

gunicorn: command not found on Render: add gunicorn to requirements.txt.

“Publish Directory required”: you chose Static Site; switch to Web Service for Flask.

Service Root Directory ... is missing: the “Root Directory” value doesn’t exist in your repo—clear it or set to the correct subfolder.



### Acknowledgements

Built as a small capstone exploring Flask, SQLAlchemy, and deployment to Render.