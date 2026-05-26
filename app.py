import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

app = Flask(__name__)

# Security Configuration
app.config['SECRET_KEY'] = os.urandom(32) # Cryptographically secure session key
app.config.update(
    SESSION_COOKIE_SECURE=True,    # Ensures cookies are only sent over HTTPS
    SESSION_COOKIE_HTTPONLY=True,  # Prevents JavaScript from accessing cookies (XSS defense)
    SESSION_COOKIE_SAMESITE='Lax', # Prevents CSRF attacks via cross-site requests
)

ph = PasswordHasher()
DATABASE = 'secure_users.db'

# Helper function to connect safely to SQLite
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# Database Setup (Runs when starting the app for demonstration purposes)
def init_db():
    with get_db_connection() as conn:
        with open('schema.sql', mode='r') as f:
            conn.cursor().executescript(f.read())
        
        # Insert a sample user into the system securely
        # Plain text password 'SuperSecret123!' gets securely Argon2 hashed here
        hashed = ph.hash("SuperSecret123!")
        conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", ("admin", hashed))
        conn.commit()

# Simplistic CSRF Token Generation manually tied to flask session 
@app.context_processor
def inject_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = os.urandom(16).hex()
    return dict(csrf_token=lambda: session['csrf_token'])

# --- ROUTES ---

@app.route('/')
def index():
    if 'user' in session:
        return f"Welcome logged in user: {session['user']}! <br><a href='/logout'>Logout</a>"
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # 1. CSRF Verification
        user_csrf = request.form.get('csrf_token')
        if not user_csrf or user_csrf != session.get('csrf_token'):
            return "CSRF Token Invalid or Missing", 403

        username = request.form.get('username')
        password = request.form.get('password')

        # 2. Parameterized Query (Prevents SQL Injection)
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        # 3. Dummy hash to prevent timing attacks
        dummy_hash = "$argon2id$v=19$m=65536,t=3,p=4$anVzdGFkdW1teXNhbHQ$fakehashval"

        # 4. Safe Hashing Verification Process
        if user:
            try:
                if ph.verify(user['password_hash'], password):
                    # Login Success: Regenerate session to prevent session fixation
                    session.clear()
                    session['user'] = user['username']
                    session['csrf_token'] = os.urandom(16).hex() # Fresh token
                    return redirect(url_for('index'))
            except VerifyMismatchError:
                pass
        else:
            # Run hashing simulation even if user not found to defeat timing analysis
            try: ph.verify(dummy_hash, "dummy_password") 
            except VerifyMismatchError: pass

        # 5. Generic Error Message (Prevents Username Enumeration)
        flash("Invalid username or password.")
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    # Initialize DB files and inject default user for initial local tests
    if not os.path.exists(DATABASE):
        init_db()
    
    # Note: For production use, debug must be set to False
    app.run(debug=True)