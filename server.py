#Imports
from flask import Flask
from flask import render_template, abort, redirect, url_for, flash, request, make_response, g, Response, send_file
import os
from dotenv import load_dotenv
from webforms import LoginForm, RegisterForm, BlogForm, CommentForm
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc, or_
from flask_migrate import Migrate
from datetime import datetime, UTC
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
import json
import re
import uuid
from functools import wraps
from flask import abort
from flask_login import current_user
from flask_wtf import CSRFProtect
from datetime import datetime, timezone
from werkzeug.exceptions import HTTPException
import logging


load_dotenv()

basedir = os.path.abspath(os.path.dirname(__file__))

#.env variables
SECRET_KEY = os.getenv("SECRET_KEY")
RECAPTCHA_PUBLIC_KEY = os.getenv("RECAPTCHA_PUBLIC_KEY")
RECAPTCHA_PRIVATE_KEY = os.getenv("RECAPTCHA_PRIVATE_KEY")

#Admin Tools------------------

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not getattr(current_user, 'is_admin', False):
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return wrapper

#--------------------------------

#Requires Verification
def Verification_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not getattr(current_user, 'is_verified', False):
            return(render_template("verification_required.html", pageName="Verification Required!"))
        return f(*args, **kwargs)
    return wrapper


#Setup
app = Flask(__name__, template_folder="site_files")
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SECRET_KEY"] = SECRET_KEY
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.join(basedir, 'instance', 'data.db')}"
app.config['TRAP_HTTP_EXCEPTIONS']=True
app.config["DEBUG"] = False
app.config["RECAPTCHA_PUBLIC_KEY"] = RECAPTCHA_PUBLIC_KEY
app.config["RECAPTCHA_PRIVATE_KEY"] = RECAPTCHA_PRIVATE_KEY
app.url_map.strict_slashes = False

# Secure session cookie settings
app.config.update(
    SESSION_COOKIE_SECURE=True,    # Only over HTTPS
    SESSION_COOKIE_HTTPONLY=True,  # Prevent JS access
    SESSION_COOKIE_SAMESITE='Lax', # CSRF protection
)

# Initialize CSRF protection
csrf = CSRFProtect(app)

#Initialize Database
db = SQLAlchemy(app)
migrate = Migrate(app, db)

#User DB Model
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32), nullable=False)
    email = db.Column(db.String(128), nullable=False, unique=True)
    date_added = db.Column(db.DateTime, default=datetime.now(UTC))

    is_admin = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)

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
    date_posted = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


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
login_manager.session_protection = "strong"

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

#Home Page
@app.route("/")
def index():
    latest_blogs = Blogs.query.order_by(Blogs.date_posted.desc()).limit(3).all()

    # Create a list of dicts with author names
    blogs_with_authors = []
    for blog in latest_blogs:
        author_info = Users.query.filter_by(id=blog.author).first()
        author_name = author_info.name if author_info else "Unknown"
        blogs_with_authors.append({
            "blog": blog,
            "author_name": author_name
        })
    return render_template("index.html", pageName="Home", blogs_with_authors=blogs_with_authors)

#About Page
@app.route("/about")
def about():
    return(render_template("about.html", pageName="About"))

#Projects Page
@app.route("/projects")
def projects():
    return(render_template("projects.html", pageName="Projects"))

@app.route("/projects/website")
def project_website():
    return(render_template("project_website.html", pageName="Projects - This Website"))

#Blog Page
from sqlalchemy import or_, func
import re

@app.route("/blog")
def blog():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    search_query = request.args.get('search', '', type=str)

    query = Blogs.query

    if search_query:
        if search_query.startswith("USER:"):
            # Extract username
            search_query_name = search_query[len("USER:"):].strip()
            
            # Find user(s) matching that name
            user_list = Users.query.filter(Users.name.ilike(f"%{search_query_name}%")).order_by(Users.date_added).all()
            user_ids = [user.id for user in user_list]

            if user_ids:
                # Filter blogs by these author IDs only
                query = query.filter(Blogs.author.in_(user_ids))
            else:
                flash("No results for that user, make sure you typed it in correctly")
                # Fallback to searching title/body using the entered text
                query = query.filter(
                    or_(
                        Blogs.title.ilike(f"%{search_query_name}%"),
                        Blogs.body.ilike(f"%{search_query_name}%")
                    )
                )
        elif search_query.startswith("EXACTUSER:"):
                    # Extract username
            search_query_name = search_query[len("EXACTUSER:"):].strip()
            
            # Find user(s) matching that name
            user_list = Users.query.filter(Users.name == search_query_name).order_by(Users.date_added).all()
            user_ids = [user.id for user in user_list]

            if user_ids:
                # Filter blogs by these author IDs only
                query = query.filter(Blogs.author.in_(user_ids))
            else:
                flash("No results for that user, make sure you typed it in correctly")
                # Fallback to searching title/body using the entered text
                query = query.filter(
                    or_(
                        Blogs.title.ilike(f"%{search_query_name}%"),
                        Blogs.body.ilike(f"%{search_query_name}%")
                    )
                )
        else:
            # General search in title/body
            query = query.filter(
                or_(
                    Blogs.title.ilike(f"%{search_query}%"),
                    Blogs.body.ilike(f"%{search_query}%")
                )
            )

    pagination = query.order_by(Blogs.date_posted.desc()).paginate(page=page, per_page=per_page, error_out=False)
    blogs = pagination.items

    return render_template("blog.html", pageName="Blog", blogs=blogs, search_query=search_query, pagination=pagination)

@app.route("/blog/<slug>", methods=["GET", "POST"])
def blog_read(slug):
    # Find blog by its slug
    blog = Blogs.query.filter_by(slug=slug).first()
    if blog is None:
        abort(404)

    # Get author info
    author_info = Users.query.filter_by(id=blog.author).first()
    author = author_info.name if author_info else "Unknown"
    author_id = int(author_info.id) if author_info else None

    form = CommentForm()
    if current_user and form.validate_on_submit():
        comment = Comments(
            body=form.body.data,
            post_id=blog.id,
            user_id=current_user.id
        )
        db.session.add(comment)
        db.session.commit()
        flash("Posted Comment")
        form.body.data = ""
        return redirect(url_for("blog_read", slug=slug))

    # --- Pagination ---
    page = request.args.get('page', 1, type=int)
    per_page = 5  # number of comments per page

    comments_pagination = Comments.query.filter_by(post_id=blog.id).order_by(Comments.date_posted.asc()).paginate(page=page, per_page=per_page)
    
    # Format comments
    comments_full = []
    for comment in comments_pagination.items:
        user = Users.query.filter_by(id=comment.user_id).first()
        comments_full.append({
            "body": comment.body,
            "author_name": user.name if user else "Unknown",
            "date_posted": comment.date_posted.strftime("%Y-%m-%d %H:%M:%S")
        })

    # Blog post date
    date_posted = blog.date_posted.strftime("%Y-%m-%d %H:%M:%S")

    return render_template(
        "blog_read.html",
        pageName="Blog",
        blog=blog,
        form=form,
        author=author,
        author_id=author_id,
        comments=comments_full,
        comments_pagination=comments_pagination,
        date_posted=date_posted
    )


#Deletes Blog post
@app.route("/blog/delete/<id>", methods=['GET', 'POST'])
@Verification_required
@login_required
def delete_blog(id):
    #Search for blog
    blog = Blogs.query.filter_by(id=id).first()

    #Ask user if they want to delete the post
    if request.method == 'POST':
        user_choice = request.form.get('choice')
        if user_choice == 'yes':
            #Check if blog exists
            if blog == None:
                flash("<strong>An error occurred!</stong> Plese try again")
                return(redirect(url_for("blog")))
            else:
                #Get comments associated with blog post
                comments = Comments.query.filter_by(post_id=id) 

                #Check if user is author
                if int(current_user.id) == int(blog.author):
                    #Delete blog post
                    db.session.delete(blog)
                    db.session.commit()

                    #Delete comments associated with blog post
                    for comment in comments:
                        db.session.delete(comment)
                        db.session.commit()

                    flash(f"Blog {blog.title} deleted!")
                    return(redirect(url_for("blog")))
                else:
                    abort(401)
        else:
            return(redirect(url_for("blog_read",slug=blog.slug)))
    return render_template("confirm.html", pageName="Confirm")
    
    
@app.route("/blog/post", methods=["GET", "POST"])
@Verification_required
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
        #      Replaces all non allowed charaters
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
        return(redirect(url_for("blog_read", slug=slug)))

    return(render_template("blog_post.html", pageName="Blog", form=form))
        

#Contact Page
@app.route("/contact")
@login_required
def contact():
    #No api available :(
    instagram = {
        "username": "pickled08",
        "followers": "117",
        "posts": 31
    }

    # GitHub stats will be fetched via front-end JS
    github = {
        "username": "Pickled08"
    }

    return(render_template("contact.html", pageName="Contact", instagram=instagram, github=github))

#Github Link
@app.route("/github")
def github():
    return redirect("https://github.com/Pickled08")

#Sitemap
@app.route("/sitemap")
def sitemap():
    return(send_file("site_files/sitemap.xml"))

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
    form = RegisterForm()

    if form.validate_on_submit():
        email = form.email.data.lower()
        existing_user = Users.query.filter_by(email=email).first()

        if existing_user:
            flash("Email already registered.")
            return render_template("register.html", pageName="Register", exists=True, form=form)

        # Create user using password setter
        user = Users(name=form.name.data, email=email)
        user.password = form.password_hash.data  # automatically hashes via setter

        try:
            db.session.add(user)
            db.session.commit()
            flash("Account registered successfully! Please log in.")
            return redirect(url_for("login"))
        except Exception as e:
            db.session.rollback()
            flash(f"Error creating account: {e}")
            print("DB error:", e)

    # Debug info if form fails validation
    elif request.method == "POST":
        print("Form errors:", form.errors)

    return render_template("register.html", pageName="Register", form=form)


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
    
#Account Page
@app.route("/account")
@login_required
def account():
    number_of_blogs = Blogs.query.filter_by(author=current_user.id).count()
    number_of_comments = Comments.query.filter_by(user_id=current_user.id).count()
    
    return render_template("account.html", pageName="Account", number_of_blogs=number_of_blogs, number_of_comments=number_of_comments)

# HTTP errors (4xx / some 5xx)
@app.errorhandler(HTTPException)
def handle_http_error(e):
    code = e.code or 500

    if code >= 500:
        logging.error("HTTP %s error", code, exc_info=True)
    else:
        logging.warning("HTTP %s: %s", code, e)

    if code == 401:
        resp = make_response(
            render_template("error_codes/401.html"),
            401
        )
    elif code == 404:
        resp = make_response(
            render_template("error_codes/404.html"),
            404
        )
    else:
        resp = make_response(
            render_template(
                "error_codes/generic_error.html",
                pageName=str(code),
                errorTitle="Error"
            ),
            code
        )

    resp.headers["Cache-Control"] = "no-store"
    return resp


# Non-HTTP exceptions → real 500s
@app.errorhandler(Exception)
def handle_unexpected_error(e):
    logging.critical("Unhandled exception", exc_info=True)

    resp = make_response(
        render_template(
            "error_codes/generic_error.html",
            pageName="500",
            errorTitle="Internal Server Error"
        ),
        500
    )
    resp.headers["Cache-Control"] = "no-store"
    return resp

@app.before_request
def log_request_id():
    g.request_id = request.headers.get("CF-Ray", "local")

#Admin Page
@app.route("/admin")
@login_required
@admin_required
def admin():
    return(render_template("admin/admin_dashboard.html"))


# Admin Pages
@app.route("/admin/<page>")
@login_required
@admin_required
def admin_pages(page):
    # Lowercase to avoid accidental caps
    page = page.lower()

    # User management page
    if page == "users":
        # Pagination vars
        page_num = request.args.get('page', 1, type=int)
        per_page = 20

        search_query = request.args.get('search', '', type=str)

        # Initialize the query
        query = Users.query

        # Filter if search term exists
        if search_query:
            query = query.filter(
                or_(
                    Users.name.ilike(f"%{search_query}%"),
                    Users.email.ilike(f"%{search_query}%")
                )
            )

        # Paginate results
        pagination = query.order_by(Users.date_added).paginate(
            page=page_num,
            per_page=per_page,
            error_out=False
        )
        registeredUsers = pagination.items

        # Render template
        return render_template(
            "admin/admin_dashboard_userlist.html",
            registeredUsers=registeredUsers,
            pagination=pagination,
            search_query=search_query
        )

    # If the page is unknown, return 404
    abort(404)


# Delete user (secure version)
@app.route("/admin/users/delete/<user_id>", methods=["GET", "POST"], endpoint="admin_delete_user")
@login_required
def admin_delete_user(user_id):
    user = Users.query.get(user_id)

    # Prevent admin from deleting themselves
    if user.id == current_user.id:
        flash("You cannot delete yourself.")
        return redirect(url_for("admin_pages", page="users"))

    # POST: confirm deletion
    if request.method == "POST":
        user_choice = request.form.get("choice")
        if user_choice == "yes":
            try:
                # Delete comments
                Comments.query.filter_by(user_id=user.id).delete()
                # Delete blogs
                Blogs.query.filter_by(author=user.id).delete()
                # Delete user
                db.session.delete(user)
                db.session.commit()

                flash(f"User {user.name} deleted successfully.")
                return redirect(url_for("admin_pages", page="users"))
            except Exception as e:
                db.session.rollback()
                flash(f"An error occurred: {str(e)}")
                return redirect(url_for("admin_pages", page="users"))
        else:
            return redirect(url_for("admin_pages", page="users"))

    # GET: show confirmation page
    return render_template("confirm.html", pageName="Confirm")

# Verify user (secure version)
@app.route("/admin/users/verify/<user_id>", methods=["GET", "POST"], endpoint="admin_verify_user")
@login_required
@admin_required
def admin_verify_user(user_id):
    user = Users.query.get(user_id)

    # POST: confirm deletion
    if request.method == "POST":
        user_choice = request.form.get("choice")
        if user_choice == "yes":
            try:
                # Mark user as verified
                user.is_verified = True

                # Commit the change
                db.session.commit()

                flash(f"User {user.name} verified successfully.")
                return redirect(url_for("admin_pages", page="users"))
            except Exception as e:
                db.session.rollback()
                flash(f"An error occurred: {str(e)}")
                return redirect(url_for("admin_pages", page="users"))
        else:
            return redirect(url_for("admin_pages", page="users"))

    # GET: show confirmation page
    return render_template("confirm.html", pageName="Confirm")

#Verified Check Page
@app.route("/verified-check")
@login_required
@Verification_required
def verified_area():
    return "You are verified!"

@app.route("/googleb06d0983f852e6e7.html")
def google_verification():
    return render_template("se/googleb06d0983f852e6e7.html")

@app.route("/health", methods=["GET"])
def health():
    return Response(
        "ok",
        status=200,
        mimetype="text/plain",
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"
        }
    )



#Functions to run the server
def run():
  #App Run parameters
  app.run(host='0.0.0.0',port=8080)
  
if __name__ == "__main__":
    run()