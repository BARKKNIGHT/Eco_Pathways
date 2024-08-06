from flask import Flask, render_template, request, redirect, session, abort,url_for
from flask_login import login_required, LoginManager, UserMixin, login_user, logout_user,current_user
from flask_session import Session
from cs50 import SQL
import hashlib
import secrets
import os
import sqlite3

app = Flask(__name__)

# Configuration
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SECRET_KEY'] = secrets.token_hex(16)
Session(app)

# Flask-Login configuration
login_manager = LoginManager()
login_manager.init_app(app)

# Database setup
DATABASE = "users.db"

def init_db():
    if not os.path.exists(DATABASE):
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT NOT NULL,
            password TEXT NOT NULL,
            salt TEXT NOT NULL,
            carbon_footprint INTEGER DEFAULT 0
        )
        ''')
        conn.commit()
        conn.close()

init_db()
db = SQL(f"sqlite:///{DATABASE}")

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id):
        self.id = id

# Password hashing functions
def hashing_password(password):
    salt = secrets.token_hex(16)
    hashed = hashlib.sha256((password + salt).encode()).hexdigest()
    return salt, hashed

def login_hash(password, salt):
    return hashlib.sha256((password + salt).encode()).hexdigest()

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('map'))
    return render_template("index.html")

@app.route('/about')
def about():
    return render_template('about.html',USER_INFO=session.get('name'))

@app.route('/contact')
def contact():
    return render_template('contact.html',USER_INFO=session.get('name'))

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        user = request.form['user']
        password = request.form['pass']
        session['name'] = user

        try:
            cursor = db.execute('SELECT user, password, salt FROM users WHERE user = ?', user)
            if cursor:
                salt = cursor[0]['salt']
                hashed_password = login_hash(password, salt)
                if hashed_password == cursor[0]['password']:
                    user_obj = User(user)
                    login_user(user_obj)
                    return render_template('maps.html', USER_INFO=session['name'])
                else:
                    return render_template('index.html', error="INCORRECT LOGIN INFORMATION!")
            else:
                return render_template('index.html', error="USER DOESN'T EXIST!")
        except Exception as e:
            return render_template('index.html', error=str(e))
    else:
        return redirect('/')

@app.route('/logout',methods=['POST','GET'])
def logout():
    data = session.get('name')
    session.clear()
    logout_user()
    return render_template('logout.html', user=data)

@app.route('/user', methods=['GET'])
@login_required
def user_data():
    return render_template('user.html', USER_INFO=session.get('name'))

@app.route('/delete', methods=['POST'])
@login_required
def delete():
    if request.method == 'POST':
        db.execute('DELETE FROM users WHERE user = ?', session.get('name'))
        return redirect('/logout')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user = request.form['user']
        password = request.form['pass']
        salt, hashed_password = hashing_password(password)

        try:
            cursor = db.execute('SELECT * FROM users WHERE user = ?', user)
            if not cursor:
                db.execute('INSERT INTO users (user, password, salt) VALUES (?, ?, ?)', user, hashed_password, salt)
                return render_template('index.html', error='Registration successful')
            else:
                return render_template('register.html', error='User already exists')
        except Exception as e:
            return render_template('register.html', error=str(e))
    else:
        return render_template("register.html")

@app.route('/map')
@login_required
def map():
    return render_template("maps.html",USER_INFO=session['name'])

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html', error=e.code), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('404.html', error=e.code), 500
@app.route('/leaderboard')
def leaderboard():
        # Retrieve the leaderboard data from the database
        leaderboard_data = db.execute('SELECT user, carbon_footprint FROM users ORDER BY carbon_footprint DESC')

        # Render the leaderboard template with the data
        return render_template('leaderboard.html', leaderboard_data=leaderboard_data,User_Info=session.get('name'))


@app.route('/update_carbon_footprint', methods=['POST'])
@login_required
def update_carbon_footprint():
    if request.method == 'POST':
        carbon_footprint = request.form['carbon_footprint']

        try:
            # Update the carbon footprint for the current user in the database
            db.execute('UPDATE users SET carbon_footprint = ? WHERE user = ?', carbon_footprint, session.get('name'))
            return redirect(url_for('user_data'))
        except Exception as e:
            return render_template('user.html', error=str(e))
    else:
        return redirect('/')
@app.errorhandler(401)
def unauthorized(e):
    return render_template('404.html', error=e.code), 401

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

if __name__ == "__main__":
    # from waitress import serve
    # serve(app, host="0.0.0.0", port=443)
    app.run(host="0.0.0.0",port=80,debug=True)
