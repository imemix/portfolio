from flask import Flask, render_template, request
from utils import DISCORD_WEBHOOK_URL, encrypt_message, decrypt_message
import requests
import re

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')







@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/visualization')
def visualization():
    """    Route for visualization page.
    This can be expanded to include dynamic visualizations or static content.   """
    # Placeholder for visualization content
    # For now, just render a static page
    
    return render_template('visualization.html')


@app.route('/projects')
def projects():
    # This route can be expanded to include dynamic project data
    projects_data = [
        {"name": "Text Based Mafia Game", "language": "Python"},
        {"name": "Chat Application", "language": "Python"},
        {"name": "Interactive Quiz", "language": "Python"},
        {"name": "Weather App", "language": "API"},
        {"name": "Recipe Finder", "language": "Web App"},
        {"name": "Portfolio Website", "language": "Showcase"}
    ]
    
    return render_template('projects.html', projects=projects_data)








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
