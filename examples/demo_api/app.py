"""
Chaos Kitten Demo API - Intentionally Vulnerable Flask Application

⚠️ WARNING: This API contains INTENTIONAL security vulnerabilities for testing purposes.
DO NOT deploy this in production. Use only for local Chaos Kitten testing.

Vulnerabilities included:
- SQL Injection (login, search endpoints)
- IDOR (user profile endpoint)
- XSS (comment endpoint)
- Missing authentication on sensitive endpoints
"""

import os
import sqlite3

from flask import Flask, g, jsonify, request

app = Flask(__name__)
DATABASE = os.path.join(os.path.dirname(__file__), 'demo.db')
_db_initialized = False


def get_db():
    """Get database connection."""
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    """Close database connection on app teardown."""
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    """Initialize the database with sample data."""
    with app.app_context():
        db = get_db()
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT,
                role TEXT DEFAULT 'user'
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                content TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                price REAL,
                description TEXT
            )
        """)

        # Insert sample data
        try:
            db.execute(
                "INSERT INTO users (username, password, email, role) VALUES ('admin', 'admin123', 'admin@chaos.kitten', 'admin')"
            )
            db.execute(
                "INSERT INTO users (username, password, email, role) VALUES ('alice', 'password123', 'alice@example.com', 'user')"
            )
            db.execute(
                "INSERT INTO users (username, password, email, role) VALUES ('bob', 'secret456', 'bob@example.com', 'user')"
            )
            db.execute(
                "INSERT INTO products (name, price, description) VALUES ('Catnip Premium', 29.99, 'The finest catnip for discerning cats')"
            )
            db.execute(
                "INSERT INTO products (name, price, description) VALUES ('Scratching Post Deluxe', 89.99, 'Ultimate scratching experience')"
            )
            db.commit()
        except sqlite3.IntegrityError:
            pass  # Data already exists


@app.before_request
def ensure_db_initialized():
    """Initialize demo DB when running under flask run (no __main__ block)."""
    global _db_initialized
    if _db_initialized:
        return
    init_db()
    _db_initialized = True


# =====================================================
# VULNERABLE ENDPOINTS - For Chaos Kitten Testing
# =====================================================


@app.route("/api/login", methods=["POST"])
def login():
    """
    🔴 VULNERABLE: SQL Injection
    The username field is directly interpolated into the SQL query.
    """
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")

    # VULNERABLE: String interpolation in SQL query
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

    db = get_db()
    try:
        user = db.execute(query).fetchone()
        if user:
            return jsonify(
                {
                    "success": True,
                    "message": f"Welcome back, {user['username']}!",
                    "user_id": user["id"],
                    "role": user["role"],
                }
            )
        return jsonify({"success": False, "message": "Invalid credentials"}), 401
    except Exception as e:
        # VULNERABLE: Exposing SQL error details
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/users/<int:user_id>", methods=["GET"])
def get_user(user_id):
    """
    🔴 VULNERABLE: IDOR (Insecure Direct Object Reference)
    No authorization check - any user can access any profile.
    """
    db = get_db()
    user = db.execute(
        "SELECT id, username, email, role FROM users WHERE id=?", (user_id,)
    ).fetchone()

    if user:
        return jsonify(
            {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "role": user["role"],
            }
        )
    return jsonify({"error": "User not found"}), 404


@app.route("/api/users", methods=["GET"])
def list_users():
    """
    🔴 VULNERABLE: No authentication required
    Exposes all user data without any auth check.
    """
    db = get_db()
    users = db.execute("SELECT id, username, email, role FROM users").fetchall()
    return jsonify([dict(u) for u in users])


@app.route("/api/search", methods=["GET"])
def search_products():
    """
    🔴 VULNERABLE: SQL Injection
    Search query is directly interpolated into SQL.
    """
    query = request.args.get("q", "")

    # VULNERABLE: String interpolation in SQL query
    sql = f"SELECT * FROM products WHERE name LIKE '%{query}%' OR description LIKE '%{query}%'"

    db = get_db()
    try:
        products = db.execute(sql).fetchall()
        return jsonify([dict(p) for p in products])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/comments", methods=["POST"])
def add_comment():
    """
    🔴 VULNERABLE: Stored XSS
    Comment content is stored without sanitization.
    """
    data = request.get_json() or {}
    user_id = data.get("user_id", 1)
    content = data.get("content", "")

    # VULNERABLE: No input sanitization
    db = get_db()
    db.execute(
        "INSERT INTO comments (user_id, content) VALUES (?, ?)", (user_id, content)
    )
    db.commit()

    return jsonify({"success": True, "message": "Comment added"})


@app.route("/api/comments", methods=["GET"])
def get_comments():
    """
    🔴 VULNERABLE: XSS - Returns unsanitized content
    """
    db = get_db()
    comments = db.execute("""
        SELECT c.id, c.content, c.created_at, u.username 
        FROM comments c 
        LEFT JOIN users u ON c.user_id = u.id
    """).fetchall()

    # VULNERABLE: Returns raw HTML content
    return jsonify(
        [
            {
                "id": c["id"],
                "content": c["content"],  # Not sanitized!
                "author": c["username"],
                "created_at": c["created_at"],
            }
            for c in comments
        ]
    )


@app.route("/api/admin/delete-user/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    """
    🔴 VULNERABLE: Missing authentication/authorization
    Admin endpoint accessible without any auth.
    """
    db = get_db()
    db.execute("DELETE FROM users WHERE id=?", (user_id,))
    db.commit()
    return jsonify({"success": True, "message": f"User {user_id} deleted"})


# =====================================================
# SAFE ENDPOINTS - For comparison
# =====================================================


@app.route("/api/products", methods=["GET"])
def list_products():
    """Safe endpoint using parameterized queries."""
    db = get_db()
    products = db.execute("SELECT * FROM products").fetchall()
    return jsonify([dict(p) for p in products])


@app.route("/api/health", methods=["GET"])
def health_check():
    """Health check endpoint."""
    return jsonify(
        {
            "status": "healthy",
            "app": "Chaos Kitten Demo API",
            "version": "1.0.0",
            "warning": "⚠️ This API is intentionally vulnerable!",
        }
    )


@app.route("/")
def index():
    """Welcome page."""
    return jsonify(
        {
            "message": "🐱 Welcome to Chaos Kitten Demo API",
            "description": "An intentionally vulnerable API for testing",
            "endpoints": {
                "POST /api/login": "User login (SQL Injection vulnerable)",
                "GET /api/users": "List all users (No auth)",
                "GET /api/users/<id>": "Get user by ID (IDOR vulnerable)",
                "GET /api/search?q=": "Search products (SQL Injection)",
                "POST /api/comments": "Add comment (XSS vulnerable)",
                "GET /api/comments": "List comments (Returns XSS)",
                "DELETE /api/admin/delete-user/<id>": "Delete user (No auth)",
                "GET /api/products": "List products (Safe)",
                "GET /api/health": "Health check",
            },
        }
    )


if __name__ == "__main__":
    init_db()
    print("🐱 Chaos Kitten Demo API starting...")
    print("⚠️  WARNING: This API is intentionally vulnerable!")
    print("📍 Running on http://localhost:5000")
    app.run(debug=True, port=5000)
