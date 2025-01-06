from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token
from werkzeug.security import generate_password_hash, check_password_hash
from oauthlib.oauth2 import WebApplicationClient
import requests
import os

# Flask Application Setup
app = Flask(__name__)

# Application Configuration
app.secret_key = os.getenv("SECRET_KEY", "cd7eb35468a7e939628b776014a1c033")  # Default fallback for local dev
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///användare.db"
app.config["JWT_SECRET_KEY"] = os.getenv(
    "JWT_SECRET_KEY", "c2e10cf127bc826f09fdf0bada9125f081b54c798d5ce1b2888f974a6092d05a"
)

# Initialize Extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)

# Google OAuth2 Configuration
GOOGLE_CLIENT_ID = os.getenv(
    "GOOGLE_CLIENT_ID",
    "216513476074-2g3ua2sboin4g8f16n8mdf9o2h1tbn0q.apps.googleusercontent.com"
)
GOOGLE_CLIENT_SECRET = os.getenv(
    "GOOGLE_CLIENT_SECRET",
    "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"
)
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

client = WebApplicationClient(GOOGLE_CLIENT_ID)

# Database Model for Users
class Anvandare(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    losenord = db.Column(db.String(200), nullable=False)

# Routes
@app.route("/")
def index():
    logged_in = "user_email" in session
    return render_template("index.html", logged_in=logged_in)

@app.route("/loggain", methods=["GET", "POST"])
def loggain():
    if request.method == "POST":
        if "register" in request.form:
            email = request.form.get("email")
            losenord = request.form.get("losenord")
            existing_user = Anvandare.query.filter_by(email=email).first()
            if not existing_user:
                hashed_password = generate_password_hash(losenord)
                ny_anvandare = Anvandare(email=email, losenord=hashed_password)
                db.session.add(ny_anvandare)
                db.session.commit()
                return redirect(url_for("index"))
            else:
                return render_template("loggain.html", fel="E-post finns redan.")
        elif "login" in request.form:
            email = request.form.get("email")
            losenord = request.form.get("losenord")
            anvandare = Anvandare.query.filter_by(email=email).first()
            if anvandare and check_password_hash(anvandare.losenord, losenord):
                session["user_email"] = email
                return redirect(url_for("index"))
            else:
                return render_template("loggain.html", fel="Fel e-post eller lösenord.")
    return render_template("loggain.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/google_login")
def google_login():
    google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]
    redirect_uri = request.host_url.rstrip("/") + "/google_callback"
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=redirect_uri,
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)

@app.route("/google_callback")
def google_callback():
    code = request.args.get("code")
    google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
    token_endpoint = google_provider_cfg["token_endpoint"]
    redirect_uri = request.host_url.rstrip("/") + "/google_callback"
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=redirect_uri,
        code=code,
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )
    client.parse_request_body_response(token_response.text)
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)
    användardata = userinfo_response.json()
    email = användardata["email"]

    # Save user in the database if they don't exist
    if not Anvandare.query.filter_by(email=email).first():
        ny_anvandare = Anvandare(email=email, losenord="")
        db.session.add(ny_anvandare)
        db.session.commit()

    session["user_email"] = email
    return redirect(url_for("index"))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5000, debug=True)
