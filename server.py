#Imports
from flask import Flask
from threading import Thread
from flask import render_template, abort, redirect, url_for, flash
import os
from dotenv import load_dotenv
from webforms import LoginForm, RegisterForm
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime, UTC
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user

load_dotenv()

#.env variables
SECRET_KEY = os.getenv("SECRET_KEY")
RECAPTCHA_PUBLIC_KEY = os.getenv("RECAPTCHA_PUBLIC_KEY")
RECAPTCHA_PRIVATE_KEY = os.getenv("RECAPTCHA_PRIVATE_KEY")

#Setup Variables
app = Flask(__name__)
app = Flask(__name__, template_folder="site_files")
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SECRET_KEY"] = SECRET_KEY
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config['TRAP_HTTP_EXCEPTIONS']=True
app.config["DEBUG"] = False
app.config["RECAPTCHA_PUBLIC_KEY"] = RECAPTCHA_PUBLIC_KEY
app.config["RECAPTCHA_PRIVATE_KEY"] = RECAPTCHA_PRIVATE_KEY

#Initialize Database
db = SQLAlchemy(app)
migrate = Migrate(app, db)

#Create Model
class Users(db.Model, UserMixin):
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

#Flask Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Please Login"

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

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

@app.route("/account")
def account():
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
        email = str.lower(form.email.data)
        user = Users.query.filter_by(email=email).first()
        if user is None:
            #Hash Password
            hashed_pw = generate_password_hash(form.password_hash.data, "scrypt")
            user = Users(name=form.name.data, email=email, password_hash=hashed_pw)
            db.session.add(user)
            db.session.commit()
            flash("Account Registerd")
        else:
            return render_template("register.html", pageName="Register",exists=True, form=form)
        name = form.name.data
        email = str.lower(form.email.data)
        #Clear Form
        form.name.data = ""
        form.email.data = ""
        form.password_hash.data = ""
        form.password_hash2.data = ""
        return redirect(url_for("index"))
    return render_template("register.html", pageName="Register", name=name, email=email, form=form)

#Login Page
@app.route("/login", methods=["GET", "POST"])
def login():
    email = None
    password = None
    passed = None

    form = LoginForm()
    #Validate Form
    if form.validate_on_submit():
        email = str.lower(form.email.data)
        password = form.password_hash.data
        #Clear Form
        form.email.data = ""
        form.password_hash.data = ""

        #Lookup user by email
        user = Users.query.filter_by(email=email).first()

        if user:
            if check_password_hash(user.password_hash, password):
                login_user(user, remember=True)
                flash("Logged In")
                return redirect(url_for("index"))
            else:
                flash("Worng Email or Password")
        else:
            flash("Worng Email or Password")

    return render_template("login.html", pageName="Login", form=form, email=email, passed=passed)

@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    flash("Logged Out Succefully")
    return redirect(url_for("login"))
    

#Error Pages
@app.errorhandler(Exception)
def handle_error(e):
    try:
        if e.code == 401:
            return render_template('error_codes/401.html', pageName="401"), 401
        elif e.code == 404:
            return render_template('error_codes/404.html', pageName="404"), 404
        elif e.code == 500:
            return render_template('error_codes/generic_error.html', pageName="500", errorTitle="Internal Server Error", errorExplain="The server has run into an error trying to load this page"), 500
        raise e
    except:
        return render_template('error_codes/generic_error.html', pageName=e.code, errorTitle="Error", errorExplain="An Error Occurred"), e.code

#Functions to run the server
def run():
  app.run(host='0.0.0.0',port=8080)
  
def start():
    t = Thread(target=run)
    t.start()

