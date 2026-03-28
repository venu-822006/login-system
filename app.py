from flask import Flask, redirect, url_for, render_template, request, jsonify
from authlib.integrations.flask_client import OAuth
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
from functools import wraps
import jwt
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

bcrypt = Bcrypt(app)
oauth = OAuth(app)

# MongoDB
client = MongoClient(os.getenv("MONGO_URI"))
db = client["loginDB"]
users_collection = db["users"]

# Google OAuth
google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    access_token_url='https://oauth2.googleapis.com/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    client_kwargs={'scope': 'openid email profile'}
)

# GitHub OAuth
github = oauth.register(
    name='github',
    client_id=os.getenv("GITHUB_CLIENT_ID"),
    client_secret=os.getenv("GITHUB_CLIENT_SECRET"),
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    api_base_url='https://api.github.com/'
)

# JWT protect
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token:
            return {"message": "Token missing"}, 401
        try:
            jwt.decode(token, "SECRET", algorithms=["HS256"])
        except:
            return {"message": "Invalid token"}, 401
        return f(*args, **kwargs)
    return decorated

# Routes
@app.route('/')
def home():
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

# Register
@app.route('/register', methods=['POST'])
def register():
    data = request.json

    if users_collection.find_one({"email": data['email']}):
        return jsonify({"message": "User already exists"})

    hashed = bcrypt.generate_password_hash(data['password']).decode('utf-8')

    users_collection.insert_one({
        "email": data['email'],
        "password": hashed,
        "provider": "email"
    })

    return jsonify({"message": "Registered successfully"})

# Login
@app.route('/login', methods=['POST'])
def login():
    data = request.json

    user = users_collection.find_one({"email": data['email']})

    if user and bcrypt.check_password_hash(user['password'], data['password']):
        token = jwt.encode({"email": data['email']}, "SECRET", algorithm="HS256")

        if isinstance(token, bytes):
            token = token.decode('utf-8')

        return jsonify({
            "message": "Login successful",
            "token": token
        })

    return jsonify({"message": "Invalid credentials"}), 401

# Google login
@app.route('/login/google')
def login_google():
    return google.authorize_redirect(url_for('google_callback', _external=True))

@app.route('/login/google/callback')
def google_callback():
    token = google.authorize_access_token()
    user = google.parse_id_token(token)

    email = user['email']

    jwt_token = jwt.encode({"email": email}, "SECRET", algorithm="HS256")

    return f"""
    <script>
      localStorage.setItem("token", "{jwt_token}");
      window.location.href = "/dashboard";
    </script>
    """

# GitHub login
@app.route('/login/github')
def login_github():
    return github.authorize_redirect(url_for('github_callback', _external=True))

@app.route('/login/github/callback')
def github_callback():
    token = github.authorize_access_token()
    resp = github.get('user')
    user = resp.json()

    username = user['login']

    jwt_token = jwt.encode({"email": username}, "SECRET", algorithm="HS256")

    return f"""
    <script>
      localStorage.setItem("token", "{jwt_token}");
      window.location.href = "/dashboard";
    </script>
    """

# Protected example
@app.route('/protected')
@token_required
def protected():
    return {"message": "Authorized"}

if __name__ == '__main__':
    app.run(debug=True)