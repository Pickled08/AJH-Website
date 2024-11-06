#Imports
from flask import Flask
from threading import Thread
from flask import render_template, abort, redirect, url_for, flash
import os
from dotenv import load_dotenv
from webforms import LoginForm, RegisterForm, TTSForm, BlogForm, CommentForm
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from flask_migrate import Migrate
from datetime import datetime, UTC
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
import json
from gtts import gTTS
import vlc
import re
import uuid

load_dotenv()

#.env variables
SECRET_KEY = os.getenv("SECRET_KEY")
RECAPTCHA_PUBLIC_KEY = os.getenv("RECAPTCHA_PUBLIC_KEY")
RECAPTCHA_PRIVATE_KEY = os.getenv("RECAPTCHA_PRIVATE_KEY")
ADMINS = os.getenv("ADMINS")

#Load Json from env variables
admins = json.loads(ADMINS)

#Setup
app = Flask(__name__)
app = Flask(__name__, template_folder="site_files")
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SECRET_KEY"] = SECRET_KEY
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config['TRAP_HTTP_EXCEPTIONS']=True
app.config["DEBUG"] = False
app.config["RECAPTCHA_PUBLIC_KEY"] = RECAPTCHA_PUBLIC_KEY
app.config["RECAPTCHA_PRIVATE_KEY"] = RECAPTCHA_PRIVATE_KEY
app.url_map.strict_slashes = False

#Initialize Database
db = SQLAlchemy(app)
migrate = Migrate(app, db)

#User DB Model
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

#Blog DB Model 
class Blogs(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    body = db.Column(db.Text)
    slug = db.Column(db.String(255))
    author = db.Column(db.String(255))
    date_posted = db.Column(db.DateTime, default=datetime.now(UTC))

#Comments DB Model
class Comments(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(255))
    post_id = db.Column(db.String(255))
    user_id = db.Column(db.String(255))
    date_posted = db.Column(db.DateTime, default=datetime.now(UTC))


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
    #Gets all blogs and orders them by date posted
    blogs = Blogs.query.order_by(Blogs.date_posted.desc())
    return(render_template("blog.html",pageName="Blog", blogs=blogs))

@app.route("/blog/<slug>", methods=["GET", "POST"])
def blog_read(slug):
    #Finds blog by its slug
    blog = Blogs.query.filter_by(slug=slug).first()
    #404 if no blog found
    if blog is None:
        abort(404)
    else:
        if current_user:
            #Comment Post
            body = None

            form = CommentForm()

            #Validate Form
            if form.validate_on_submit():

                #Vars
                body = form.body.data
                post_id = blog.id
                user_id = current_user.id

                comment = Comments(body=body, post_id=post_id, user_id=user_id)

                #Commits to DB
                db.session.add(comment)
                db.session.commit()
                flash("Posted Comment")

                #Clear form
                form.body.data = ""
                return(redirect(url_for("blog_read", slug=slug)))

        #Comment load
        current_post_id = blog.id
        comments = Comments.query.filter_by(post_id=current_post_id)

        #Format comment data
        comments_full = []
        for comment in comments:
            #Get user who posted comment
            user = Users.query.filter_by(id=comment.user_id).first()

            #Data
            body = comment.body
            author_name = user.name
            #Format date posted
            datePosted = str(comment.date_posted)
            datePosted = datePosted.split(".", 1)[0]
            print(datePosted)

            #Package into list
            data = [body, author_name, datePosted]
            #Add to main list
            comments_full.append(data)


        return(render_template("blog_read.html", pageName="Blog", blog=blog, form=form, comments=comments_full))

@app.route("/blog/post", methods=["GET", "POST"])
@login_required
def blog_post():
    title = None
    body = None

    form = BlogForm()

    #Validate Form
    if form.validate_on_submit():

        #Vars
        title = form.title.data
        body = form.body.data
        author = current_user.id
        #      Replaces and non allowed charaters
        #      |                  Replaces spaces with underscores
        #      |                  |                  Puts title in lowercase
        #      |                  |                  |                          Adds a UUID to the end to avoid dupicate urls
        slug = re.sub(r"\W+", "", re.sub(r"\s", "_", str.lower(title))) + "-" + str(uuid.uuid4())

        blog = Blogs(title=title, body=body, slug=slug, author=author)

        #Committs to DB
        db.session.add(blog)
        db.session.commit()
        flash("Posted Blog")

        #Clear Form
        form.title.data = ""
        form.body.data = ""

    return(render_template("blog_post.html", pageName="Blog", form=form))
        

#Contact Page
@app.route("/contact")
def contact():
    abort(404)

#Fun Stuff
@app.route("/fun")
def fun():
    return(render_template("fun.html", pageName="Fun"))

@app.route("/fun/tts", methods=["GET", "POST"])
@login_required
def fun_tts():
    input = None

    form = TTSForm()

    #Validate Form
    if form.validate_on_submit():
        input = form.input.data
        print(f"TTS: {input}")

        #Generate audio using google TTS
        tts = gTTS(input)
        tts.save("audio/output.mp3")

        #Load and Play audio
        p = vlc.MediaPlayer("audio/output.mp3")
        p.play()

    #clear Form
    form.input.data = ""

    return(render_template("fun_tts.html", pageName="Fun", input=input, form=form))

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

#Account Page
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
        
        #Redirect to homepage after submiting
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
                #Login User
                login_user(user, remember=True)
                flash("Logged In")

                #Redirect to homepage after logging in
                return redirect(url_for("index"))
            else:
                flash("Worng Email or Password")
        else:
            flash("Worng Email or Password")

    return render_template("login.html", pageName="Login", form=form, email=email, passed=passed)

#Logout
@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    #Logs out user
    logout_user()
    flash("Logged Out Succefully")

    return redirect(url_for("login"))
    

#Error Pages
@app.errorhandler(Exception)
def handle_error(e):
    try:
        #Error Page 401
        if e.code == 401:
            return render_template('error_codes/401.html', pageName="401"), 401
        
        #Error Page 404
        elif e.code == 404:
            return render_template('error_codes/404.html', pageName="404"), 404
        
        #Error Page 500
        elif e.code == 500:
            return render_template('error_codes/generic_error.html', pageName="500", errorTitle="Internal Server Error", errorExplain="The server has run into an error trying to load this page"), 500
        raise e
    
    #Any other Error
    except:
        return render_template('error_codes/generic_error.html', pageName=e.code, errorTitle="Error", errorExplain="An Error Occurred"), e.code

#Admin Page
@app.route("/admin")
@login_required
def admin():
    #Check if current user is in admin list
    for admin in admins["admins"]:
        if current_user.email == admin:
            return(render_template("admin/admin_dashboard.html"))
    else:
        abort(401)

#Admin Pages
@app.route("/admin/<page>")
@login_required
def admin_pages(page):
    #Lowercase to avoid accidently caps
    page = str.lower(page)

    #Check if current user is in admin list
    for admin in admins["admins"]:
        if current_user.email == admin:
            #User management page
            if page == "users":
                #Get all users and order by date added
                registeredUsers = Users.query.order_by(Users.date_added)
                return(render_template("admin/admin_dashboard_userlist.html", registeredUsers=registeredUsers))
    else:
        abort(401)

#Delete user
@app.route("/admin/users/delete/<id>")
@login_required
def admin_delete_user(id):
    #Check if current user is in admin list
    for admin in admins["admins"]:
        if current_user.email == admin:
            try:
                #Lookup and Delete user
                user = Users.query.filter_by(id=id).first()
                db.session.delete(user)
                db.session.commit()
                flash(f"User {id} Deleted")
                return(redirect(url_for("admin_pages", page="users")))
            
            #Error if someing goes wrong
            except:
                flash("<strong>An error occurred!</stong> Plese try again")
                return(redirect(url_for("admin_pages", page="users")))
    else:
        abort(401)

#Functions to run the server
def run():
  #App Run parameters
  app.run(host='0.0.0.0',port=8080)
  
#Start using threading
def start():
    t = Thread(target=run)
    t.start()

