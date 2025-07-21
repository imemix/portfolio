from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from utils import DISCORD_WEBHOOK_URL, GITHUB_TOKEN , encrypt_message, decrypt_message
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



def github_headers():
    return {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}

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
        {"name": "Private Commission", "language": "Contact", "link": "/contact"}
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
# API route to fetch GitHub repos
@app.route('/api/github/repos/<username>')
def api_github_repos(username):
    url = f"https://api.github.com/users/{username}/repos?per_page=100"
    resp = requests.get(url, headers=github_headers())
    if resp.status_code != 200:
        return jsonify({"error": "GitHub API error", "status": resp.status_code}), resp.status_code
    return jsonify(resp.json())

# API route to fetch GitHub commits
@app.route('/api/github/commits/<username>')
def api_github_commits(username):
    url = f"https://api.github.com/users/{username}/repos?per_page=100"
    repos_resp = requests.get(url, headers=github_headers())
    if repos_resp.status_code != 200:
        return jsonify({"error": "GitHub API error", "status": repos_resp.status_code}), repos_resp.status_code
    repos = repos_resp.json()
    commit_data = []
    for repo in repos[:50]:
        repo_name = repo['name']
        stats_url = f"https://api.github.com/repos/{username}/{repo_name}/stats/commit_activity"
        stats_resp = requests.get(stats_url, headers=github_headers())
        if stats_resp.status_code == 200:
            stats = stats_resp.json()
            commit_data.append({"repo": repo_name, "weeks": stats})
    return jsonify(commit_data)

# API route to fetch GitHub contributions
@app.route('/api/github/contributions/<username>')
def api_github_contributions(username):
    url = f"https://api.github.com/users/{username}/events/public?per_page=100"
    resp = requests.get(url, headers=github_headers())
    if resp.status_code != 200:
        return jsonify({"labels": [], "data": []})
    events = resp.json()
    months = {}
    for ev in events:
        date = ev.get("created_at")
        if date:
            dt = date[:7]  # YYYY-MM
            months[dt] = months.get(dt, 0) + 1
    sorted_months = sorted(months.items())
    last12 = sorted_months[-12:]
    return jsonify({
        "labels": [x[0] for x in last12],
        "data": [x[1] for x in last12]
    })

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
