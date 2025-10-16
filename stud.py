from flask import Flask, render_template_string, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import secrets
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import joblib
from flask import Flask, request, render_template
import datetime

# To create a datetime object:
current_time = datetime.datetime.now()
specific_date = datetime.datetime(2025, 10, 12, 21, 51, 0)
from datetime import datetime

# To create a datetime object:
current_time = datetime.now()
specific_date = datetime(2025, 10, 12, 21, 51, 0)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Change to a secure random key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    username = db.Column(db.String(100), nullable=True)
    first_name = db.Column(db.String(100), nullable=True)
    last_name = db.Column(db.String(100), nullable=True)
    reset_token = db.Column(db.String(100))
    reset_token_expiry = db.Column(db.DateTime)


# Create database tables
with app.app_context():
    db.create_all()

# SMTP configuration (replace with your own details)
SMTP_SERVER = 'smtp.gmail.com'  # Example for Gmail
SMTP_PORT = 587
SMTP_USERNAME = 'kiphillary854@gmail.com'  # Your email
SMTP_PASSWORD = 'nekhqmjseaqeqwin'  # Use app password for Gmail


def send_reset_email(to_email, token):
    msg = MIMEMultipart()
    msg['From'] = SMTP_USERNAME
    msg['To'] = to_email
    msg['Subject'] = 'Password Reset Request'

    body = f"""
    To reset your password, click the following link:
    {url_for('reset_password', token=token, _external=True)}

    If you did not request this, please ignore this email.
    """
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        text = msg.as_string()
        server.sendmail(SMTP_USERNAME, to_email, text)
        server.quit()
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False


# HTML Templates as Strings
INDEX_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Home</title>
</head>
<body style="font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 20px; display: flex; justify-content: center; align-items: center; min-height: 100vh;">
   <nav>
    <a href="{{ url_for('about') }}">ABOUT</a>
    <a href="{{ url_for('contact') }}">CONTACT</a>
  </nav>
   
    <div style="background-color: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); width: 400px; max-width: 100%; text-align: center;">
        <h1 style="color: #007bff; margin-bottom: 20px; font-size: 28px;">WELCOME TO CARPRICE PREDICTION </h1>
        <p style="color: #555; margin-bottom: 30px; font-size: 16px; line-height: 1.5;">Join us today or log in to explore our services.</p>
        <div style="display: flex; flex-direction: column; gap: 15px;">
            <a href="{{ url_for('login') }}" style="background-color: #007bff; color: white; padding: 12px; border-radius: 4px; text-decoration: none; font-size: 16px; transition: background-color 0.3s;">Login</a>
            <a href="{{ url_for('register') }}" style="background-color: #28a745; color: white; padding: 12px; border-radius: 4px; text-decoration: none; font-size: 16px; transition: background-color 0.3s;">Register</a>
            <a href="{{ url_for('forgot_password') }}" style="background-color: #dc3545; color: white; padding: 12px; border-radius: 4px; text-decoration: none; font-size: 16px; transition: background-color 0.3s;">Forgot Password?</a>
        </div>
        <style>
            a:hover { opacity: 0.9; }
        </style>
    </div>
    <style>
body {
  background-image: url('static/car1.jpg');
}
</style>
<style>
    /* Simple navigation bar styling */
    nav {
      background-color: #333;
      padding: 10px;
       position: fixed;            /* keeps the nav bar at the top */
      top: 0;
      width: 100%;    
    }

    nav a {
      color: white;
      text-decoration: none;
      margin: 0 15px;
      font-size: 18px;
        
    }

    nav a:hover {
      text-decoration: underline;
    }
  </style>

</body>
</html>
"""


REGISTER_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Register</title>
</head>
<body style="font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 20px; display: flex; justify-content: center; align-items: center; height: 100vh;">
    
  <style>
body {
  background-image: url('static/car1.jpg');
}
</style>  
    <div style="background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); width: 400px; max-width: 100%;">
        <h2 style="text-align: center; color: #333;">Register</h2>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <p style="text-align: center; color: {% if category == 'success' %}green{% else %}red{% endif %}; font-weight: bold;">{{ message }}</p>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <form method="POST" style="display: flex; flex-direction: column;">
            <label for="username" style="margin-bottom: 5px; color: #555;">Username:</label>
            <input type="text" id="username" name="username" required style="padding: 10px; margin-bottom: 15px; border: 1px solid #ccc; border-radius: 4px; font-size: 16px;">
            <label for="first_name" style="margin-bottom: 5px; color: #555;">First Name:</label>
            <input type="text" id="first_name" name="first_name" style="padding: 10px; margin-bottom: 15px; border: 1px solid #ccc; border-radius: 4px; font-size: 16px;">
            <label for="last_name" style="margin-bottom: 5px; color: #555;">Last Name:</label>
            <input type="text" id="last_name" name="last_name" style="padding: 10px; margin-bottom: 15px; border: 1px solid #ccc; border-radius: 4px; font-size: 16px;">
            <label for="email" style="margin-bottom: 5px; color: #555;">Email:</label>
            <input type="email" id="email" name="email" required style="padding: 10px; margin-bottom: 15px; border: 1px solid #ccc; border-radius: 4px; font-size: 16px;">
            <label for="password" style="margin-bottom: 5px; color: #555;">Password:</label>
            <input type="password" id="password" name="password" required style="padding: 10px; margin-bottom: 15px; border: 1px solid #ccc; border-radius: 4px; font-size: 16px;">
            <label for="confirm_password" style="margin-bottom: 5px; color: #555;">Confirm Password:</label>
            <input type="password" id="confirm_password" name="confirm_password" required style="padding: 10px; margin-bottom: 15px; border: 1px solid #ccc; border-radius: 4px; font-size: 16px;">
            <button type="submit" style="background-color: #007bff; color: white; padding: 10px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px;">Register</button>
        </form>
        <p style="text-align: center; margin-top: 15px;"><a href="{{ url_for('login') }}" style="color: #007bff; text-decoration: none;">Already have an account? Login</a></p>
    </div>
</body>
</html>
"""

LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
</head>
<body style="font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 20px; display: flex; justify-content: center; align-items: center; height: 100vh;">
    
    <style>
body {
  background-image: url('static/car1.jpg');
}
</style>
    
    <div style="background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); width: 400px; max-width: 100%;">
        <h2 style="text-align: center; color: #333;">Login</h2>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <p style="text-align: center; color: {% if category == 'success' %}green{% else %}red{% endif %}; font-weight: bold;">{{ message }}</p>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <form method="POST" style="display: flex; flex-direction: column;">
            <label for="email" style="margin-bottom: 5px; color: #555;">Email:</label>
            <input type="email" id="email" name="email" required style="padding: 10px; margin-bottom: 15px; border: 1px solid #ccc; border-radius: 4px; font-size: 16px;">
            <label for="password" style="margin-bottom: 5px; color: #555;">Password:</label>
            <input type="password" id="password" name="password" required style="padding: 10px; margin-bottom: 15px; border: 1px solid #ccc; border-radius: 4px; font-size: 16px;">
            <button type="submit" style="background-color: #007bff; color: white; padding: 10px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px;">Login</button>
        </form>
        <p style="text-align: center; margin-top: 15px;"><a href="{{ url_for('forgot_password') }}" style="color: #007bff; text-decoration: none;">Forgot Password?</a></p>
        <p style="text-align: center; margin-top: 10px;"><a href="{{ url_for('register') }}" style="color: #007bff; text-decoration: none;">Don't have an account? Register</a></p>
    </div>
</body>
</html>
"""

FORGOT_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Forgot Password</title>
</head>
<body style="font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 20px; display: flex; justify-content: center; align-items: center; height: 100vh;">
    <div style="background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); width: 400px; max-width: 100%;">
        <h2 style="text-align: center; color: #333;">Forgot Password</h2>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <p style="text-align: center; color: {% if category == 'success' %}green{% else %}red{% endif %}; font-weight: bold;">{{ message }}</p>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <form method="POST" style="display: flex; flex-direction: column;">
            <label for="email" style="margin-bottom: 5px; color: #555;">Email:</label>
            <input type="email" id="email" name="email" required style="padding: 10px; margin-bottom: 15px; border: 1px solid #ccc; border-radius: 4px; font-size: 16px;">
            <button type="submit" style="background-color: #007bff; color: white; padding: 10px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px;">Send Reset Link</button>
        </form>
        <p style="text-align: center; margin-top: 15px;"><a href="{{ url_for('login') }}" style="color: #007bff; text-decoration: none;">Back to Login</a></p>
    </div>
</body>
</html>
"""

RESET_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Reset Password</title>
</head>
<body style="font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 20px; display: flex; justify-content: center; align-items: center; height: 100vh;">
    <div style="background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); width: 400px; max-width: 100%;">
        <h2 style="text-align: center; color: #333;">Reset Password</h2>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <p style="text-align: center; color: {% if category == 'success' %}green{% else %}red{% endif %}; font-weight: bold;">{{ message }}</p>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <form method="POST" style="display: flex; flex-direction: column;">
            <label for="password" style="margin-bottom: 5px; color: #555;">New Password:</label>
            <input type="password" id="password" name="password" required style="padding: 10px; margin-bottom: 15px; border: 1px solid #ccc; border-radius: 4px; font-size: 16px;">
            <label for="confirm_password" style="margin-bottom: 5px; color: #555;">Confirm Password:</label>
            <input type="password" id="confirm_password" name="confirm_password" required style="padding: 10px; margin-bottom: 15px; border: 1px solid #ccc; border-radius: 4px; font-size: 16px;">
            <button type="submit" style="background-color: #007bff; color: white; padding: 10px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px;">Reset Password</button>
        </form>
        <p style="text-align: center; margin-top: 15px;"><a href="{{ url_for('login') }}" style="color: #007bff; text-decoration: none;">Back to Login</a></p>
    </div>
</body>
</html>
"""

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Profile Dashboard</title>
</head>
<body style="font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 20px; display: flex; justify-content: center; align-items: center; height: 100vh;">
    <div style="background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); width: 400px; max-width: 100%;">
        <h2 style="text-align: center; color: #333;">Profile Dashboard</h2>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <p style="text-align: center; color: {% if category == 'success' %}green{% else %}red{% endif %}; font-weight: bold;">{{ message }}</p>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <div style="margin-bottom: 20px;">
            <p><strong>Username:</strong> {{ user.username or 'Not set' }}</p>
            <p><strong>First Name:</strong> {{ user.first_name or 'Not set' }}</p>
            <p><strong>Last Name:</strong> {{ user.last_name or 'Not set' }}</p>
            <p><strong>Email:</strong> {{ user.email }}</p>
        </div>
        <div style="display: flex; flex-direction: column; gap: 10px;">
            <a href="{{ url_for('update_profile') }}" style="background-color: #007bff; color: white; padding: 10px; text-align: center; border-radius: 4px; text-decoration: none;">Update Profile</a>
            <a href="{{ url_for('change_password') }}" style="background-color: #28a745; color: white; padding: 10px; text-align: center; border-radius: 4px; text-decoration: none;">Change Password</a>
            <a href="{{ url_for('logout') }}" style="background-color: #dc3545; color: white; padding: 10px; text-align: center; border-radius: 4px; text-decoration: none;">Logout</a>
        </div>
    </div>
</body>
</html>
"""

UPDATE_PROFILE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Update Profile</title>
</head>
<body style="font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 20px; display: flex; justify-content: center; align-items: center; height: 100vh;">
    <div style="background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); width: 400px; max-width: 100%;">
        <h2 style="text-align: center; color: #333;">Update Profile</h2>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <p style="text-align: center; color: {% if category == 'success' %}green{% else %}red{% endif %}; font-weight: bold;">{{ message }}</p>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <form method="POST" style="display: flex; flex-direction: column;">
            <label for="username" style="margin-bottom: 5px; color: #555;">Username:</label>
            <input type="text" id="username" name="username" value="{{ user.username or '' }}" style="padding: 10px; margin-bottom: 15px; border: 1px solid #ccc; border-radius: 4px; font-size: 16px;">
            <label for="first_name" style="margin-bottom: 5px; color: #555;">First Name:</label>
            <input type="text" id="first_name" name="first_name" value="{{ user.first_name or '' }}" style="padding: 10px; margin-bottom: 15px; border: 1px solid #ccc; border-radius: 4px; font-size: 16px;">
            <label for="last_name" style="margin-bottom: 5px; color: #555;">Last Name:</label>
            <input type="text" id="last_name" name="last_name" value="{{ user.last_name or '' }}" style="padding: 10px; margin-bottom: 15px; border: 1px solid #ccc; border-radius: 4px; font-size: 16px;">
            <label for="email" style="margin-bottom: 5px; color: #555;">Email:</label>
            <input type="email" id="email" name="email" value="{{ user.email }}" required style="padding: 10px; margin-bottom: 15px; border: 1px solid #ccc; border-radius: 4px; font-size: 16px;">
            <button type="submit" style="background-color: #007bff; color: white; padding: 10px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px;">Update Profile</button>
        </form>
        <p style="text-align: center; margin-top: 15px;"><a href="{{ url_for('dashboard') }}" style="color: #007bff; text-decoration: none;">Back to Dashboard</a></p>
    </div>
</body>
</html>
"""

CHANGE_PASSWORD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Change Password</title>
</head>
<body style="font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 20px; display: flex; justify-content: center; align-items: center; height: 100vh;">
    <div style="background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); width: 400px; max-width: 100%;">
        <h2 style="text-align: center; color: #333;">Change Password</h2>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <p style="text-align: center; color: {% if category == 'success' %}green{% else %}red{% endif %}; font-weight: bold;">{{ message }}</p>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <form method="POST" style="display: flex; flex-direction: column;">
            <label for="current_password" style="margin-bottom: 5px; color: #555;">Current Password:</label>
            <input type="password" id="current_password" name="current_password" required style="padding: 10px; margin-bottom: 15px; border: 1px solid #ccc; border-radius: 4px; font-size: 16px;">
            <label for="new_password" style="margin-bottom: 5px; color: #555;">New Password:</label>
            <input type="password" id="new_password" name="new_password" required style="padding: 10px; margin-bottom: 15px; border: 1px solid #ccc; border-radius: 4px; font-size: 16px;">
            <label for="confirm_password" style="margin-bottom: 5px; color: #555;">Confirm New Password:</label>
            <input type="password" id="confirm_password" name="confirm_password" required style="padding: 10px; margin-bottom: 15px; border: 1px solid #ccc; border-radius: 4px; font-size: 16px;">
            <button type="submit" style="background-color: #007bff; color: white; padding: 10px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px;">Change Password</button>
        </form>
        <p style="text-align: center; margin-top: 15px;"><a href="{{ url_for('dashboard') }}" style="color: #007bff; text-decoration: none;">Back to Dashboard</a></p>
    </div>
</body>
</html>
"""


# Routes
@app.route('/')
def index():
    return render_template_string(INDEX_HTML)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Validate input
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
        elif password != confirm_password:
            flash('Passwords do not match.', 'error')
        else:
            # Create new user
            new_user = User(
                username=username,
                first_name=first_name,
                last_name=last_name,
                email=email,
                password=generate_password_hash(password)
            )
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))

    return render_template_string(REGISTER_HTML)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id

            return redirect(url_for('prediction'))
        else:
            flash('Invalid email or password.', 'error')
    return render_template_string(LOGIN_HTML)


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('index'))


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            token = secrets.token_urlsafe(32)
            user.reset_token = token
            user.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()

            if send_reset_email(email, token):
                flash('Reset email sent! Check your inbox.', 'success')
            else:
                flash('Error sending reset email.', 'error')
        else:
            flash('Email not found.', 'error')
        return redirect(url_for('forgot_password'))

    return render_template_string(FORGOT_HTML)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    if not user or user.reset_token_expiry < datetime.utcnow():
        flash('Invalid or expired token.', 'error')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        if password == confirm_password:
            user.password = generate_password_hash(password)
            user.reset_token = None
            user.reset_token_expiry = None
            db.session.commit()
            flash('Password reset successfully!', 'success')
            return redirect(url_for('login'))
        else:
            flash('Passwords do not match.', 'error')

    return render_template_string(RESET_HTML, token=token)


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to access the dashboard.', 'error')
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    return render_template_string(DASHBOARD_HTML, user=user)

@app.route('/prediction')
def predict():
    print(current_user.name)
    return render_template("prediction.html")

model  = joblib.load('Prediction_Model')

@app.route('/contact', methods=['GET'])
def contact():
    return render_template("contact.html")
@app.route('/about', methods=['GET'])
def about():
    return render_template("about.html")

@app.route('/predict', methods=['GET', 'POST'])
def prediction():
    if request.method == 'POST':
        price = float(request.form['price'])
        kms = float(request.form['kms'])
        fuel = request.form['fuel']
        seller = request.form['seller']
        mode = request.form['mode']
        own = int(request.form['own'])
        year = request.form['year']
        current_year = datetime.now().year
        age = current_year - int(year)

        # fuel

        if (fuel == 'Hybrid'):
            fuel = 2
        elif (fuel == 'Diesel'):
            fuel = 1
        else:
            fuel = 0

        # seller

        if (seller == 'Dealer'):
            seller = 0
        else:
            seller = 1

        # mode

        if (mode == 'Manual'):
            mode = 0
        else:
            mode = 1

        prediction = model.predict([[price, kms, fuel, seller, mode, own, age]])
        final_price = round(prediction[0], 2)

        return render_template("prediction.html", prediction_text=" {}".format(final_price))

    else:
        return render_template("prediction.html")



@app.route('/update_profile', methods=['GET', 'POST'])
def update_profile():
    if 'user_id' not in session:
        flash('Please log in to update your profile.', 'error')
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        username = request.form.get('username')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')

        # Check if email is already taken by another user
        existing_user = User.query.filter_by(email=email).first()
        if existing_user and existing_user.id != user.id:
            flash('Email already in use.', 'error')
        else:
            user.username = username
            user.first_name = first_name
            user.last_name = last_name
            user.email = email
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('dashboard'))

    return render_template_string(UPDATE_PROFILE_HTML, user=user)


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        flash('Please log in to change your password.', 'error')
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not check_password_hash(user.password, current_password):
            flash('Current password is incorrect.', 'error')
        elif new_password != confirm_password:
            flash('New passwords do not match.', 'error')
        else:
            user.password = generate_password_hash(new_password)
            db.session.commit()
            flash('Password changed successfully!', 'success')
            return redirect(url_for('dashboard'))

    return render_template_string(CHANGE_PASSWORD_HTML)


# For testing: Add a sample user if none exists
with app.app_context():
    if not User.query.filter_by(email='test@example.com').first():
        sample_user = User(
            email='test@example.com',
            password=generate_password_hash('oldpassword'),
            username='testuser',
            first_name='Test',
            last_name='User'
        )
        db.session.add(sample_user)
        db.session.commit()

if __name__ == '__main__':
    app.run(debug=True)