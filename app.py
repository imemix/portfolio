from flask import Flask, render_template, request, redirect, url_for, session
from utils import DISCORD_WEBHOOK_URL, encrypt_message, decrypt_message
import requests
import re
import sqlite3
import hashlib

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a secure random value

def get_db():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')

init_db()

def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()




# ----- routes -----

# Route for the home page
@app.route('/')
def home():
    return render_template('index.html')
# Route for the about page
@app.route('/about')
def about():
    return render_template('about.html')
# Route for the visualization page
@app.route('/visualization')
def visualization():
    """    Route for visualization page.
    This can be expanded to include dynamic visualizations or static content.   """
    # Placeholder for visualization content
    # For now, just render a static page
    return render_template('visualization.html')
# Route for projects page
@app.route('/projects')
def projects():
    # This route can be expanded to include dynamic project data
    projects_data = [
        {"name": "Text Based Mafia Game", "language": "Python", "link": "https://github.com/imemix/mafiagame"},
        {"name": "IRC Chat Client", "language": "Python", "link": "https://github.com/imemix/Chat-app"},
        {"name": "Portfolio Website", "language": "Showcase", "link": "https://github.com/imemix/portfolio"},
        {"name": "Blackmarket", "language": "Showcase", "link": "-"}
    ]
    
    return render_template('projects.html', projects=projects_data)
# Route for the contact form
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    message = None
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        user_message = request.form.get('msg')

        # Validate email
        allowed_domains = [
            "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
            "icloud.com", "protonmail.com", "aol.com"
        ]
        email_regex = r'^[\w\.-]+@([\w\.-]+\.\w+)$'
        match = re.match(email_regex, email)
        if not match or match.group(1).lower() not in allowed_domains:
            message = "Please enter a valid email."
            return render_template('contact.html', message=message)

        # Encrypt the message
        plain_text = (
            f"Name: {name}\n"
            f"Email: {email}\n"
            f"Message: {user_message}"
        )
        encrypted_text = encrypt_message(plain_text)

        # Send to Discord
        discord_data = {
            "embeds": [
                {
                    "title": "New Contact Form Submission",
                    "color": 5814783,
                    "fields": [
                        {"name": "Encrypted Data", "value": encrypted_text, "inline": False},
                        {"name": "Decrypted Data", "value": plain_text, "inline": False}
                    ],
                    "image": {
                        "url": "https://i.imgur.com/8Km9tLL.jpg"  # Example image URL, replace as desired
                    }
                }
            ]
        }
        try:
            requests.post(DISCORD_WEBHOOK_URL, json=discord_data)
        except Exception as e:
            print(f"Failed to send to Discord: {e}")

        # Decrypt for front end display
        decrypted_text = decrypt_message(encrypted_text).replace('\n', '<br>')
        message = f"Thank you, {name}! We have received your message.<br><br><strong>Encrypted:</strong><br><pre>{encrypted_text}</pre>"

    return render_template('contact.html', message=message)
# Route for user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user and user['password'] == hash_password(password):
            session['username'] = username
            return redirect(url_for('home'))
        else:
            error = "Invalid username or password."
    return render_template('login.html', error=error)
# Route for user registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            error = "Username and password required."
        else:
            db = get_db()
            try:
                db.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hash_password(password)))
                db.commit()
                session['username'] = username
                return redirect(url_for('home'))
            except sqlite3.IntegrityError:
                error = "Username already exists."
    return render_template('register.html', error=error)
# Route for user logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))
# Route for the helicopter game page
@app.route('/helicopter')
def helicopter():
    return render_template('helicopter.html')




# ----- Error handlers -----
@app.errorhandler(400)
def bad_request(e):
    return render_template('400.html'), 400

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


if __name__ == '__main__':
    app.run(debug=True)
