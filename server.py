#Imports
from flask import Flask
from threading import Thread
from flask import render_template, abort, redirect
import os
from dotenv import load_dotenv
from webforms import LoginForm, RegisterForm
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, UTC
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

#.env variables
SECRET_KEY = os.getenv("SECRET_KEY")

#Setup Variables
app = Flask(__name__)
app = Flask(__name__, template_folder="site_files")
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SECRET_KEY"] = SECRET_KEY
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"

#Initialize Database
db = SQLAlchemy(app)

#Create Model
class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32), nullable=False)
    email = db.Column(db.String(128), nullable=False, unique=True)
    date_added = db.Column(db.DateTime, default=datetime.now(UTC))

    #Password
    password_hash = db.Column(db.String(128))
    @property
    def password(self):
        raise AttributeError("Password is not a readable attribute")
    
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    #Create A String
    def __repr__(self):
        return "<name %r>" % self.name

#Home Page
@app.route("/")
def index():
    return render_template("index.html", pageName="Home")

#About Page
@app.route("/about")
def about():
    abort(404)

#Projects Page
@app.route("/projects")
def projects():
    abort(404)

#Blog Page
@app.route("/blog")
def blog():
    abort(404)

#Contact Page
@app.route("/contact")
def contact():
    abort(404)

#Github Link
@app.route("/github")
def github():
    return redirect("https://github.com/Pickled08")

#Sitemap
@app.route("/sitemap")
def sitemap():
    abort(404)

#Privacy Policy Page
@app.route("/policies/privacy")
def privacy_policy():
    abort(404)

#Cookie Policy Page
@app.route("/policies/cookies")
def cookie_policy():
    abort(404)

#Register Page
@app.route("/register", methods=["GET", "POST"])
def register():
    name = None
    email = None
    password_hash = None
    form = RegisterForm()
    #Validate Form
    if form.validate_on_submit():
        email_lc = str.lower(form.email.data)
        user = Users.query.filter_by(email=email_lc).first()
        if user is None:
            #Hash Password
            hashed_pw = generate_password_hash(form.password_hash.data, "scrypt")
            user = Users(name=form.name.data, email=email_lc, password_hash=hashed_pw)
            db.session.add(user)
            db.session.commit()
        else:
            return render_template("register.html", pageName="Register",exists=True, form=form)
        name = form.name.data
        email = str.lower(form.email.data)
        form.name.data = ""
        form.email.data = ""
        form.password_hash.data = ""
        form.password_hash2.data = ""
    return render_template("register.html", pageName="Register", name=name, email=email, form=form)

#Login Page
@app.route("/login", methods=["GET", "POST"])
def login():
    name = None
    password = None
    form = LoginForm()
    #Validate Form
    if form.validate_on_submit():
        name = form.name.data
        password_hash = form.password_hash.data
        form.name.data = ""
        form.password.data = ""
    return render_template("login.html", pageName="Login", name=name, form=form)

@app.route("/logout")
def logout():
    abort(404)

#404 Error Page
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

#Functions to run the server
def run():
  app.run(host='0.0.0.0',port=8080)
  
def start():
    t = Thread(target=run)
    t.start()

