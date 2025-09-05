-- # Create a PostgreSQL-compatible version
-- cat > supabase_schema.sql << 'EOF'
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL,
    password VARCHAR(100) NOT NULL,
    created_at TIMESTAMP
);

CREATE TABLE sessions (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP
);

CREATE TABLE books (
    id SERIAL PRIMARY KEY,
    title VARCHAR(100) NOT NULL,
    author VARCHAR(100) NOT NULL,
    description VARCHAR(1000) NOT NULL,
    genre VARCHAR(50) NOT NULL,
    cover_url VARCHAR(5000),
    file_path VARCHAR(200) NOT NULL,
    file_type VARCHAR(50) NOT NULL,
    user_id INTEGER,
    FOREIGN KEY(user_id) REFERENCES users (id)
);

CREATE TABLE feedback (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    title VARCHAR(100),
    content TEXT NOT NULL,
    created_at TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users (id)
);

CREATE TABLE ebook_links (
    id SERIAL PRIMARY KEY,
    title VARCHAR(100) NOT NULL,
    epub_link VARCHAR(255),
    pdf_link VARCHAR(255),
    book_id INTEGER NOT NULL,
    FOREIGN KEY(book_id) REFERENCES books (id)
);
