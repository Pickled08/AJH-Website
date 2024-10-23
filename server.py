#Imports
from flask import Flask
from threading import Thread
from flask import render_template, abort

#Setup Variables
app = Flask(__name__)
app = Flask(__name__, template_folder="site_files")
app.config["TEMPLATES_AUTO_RELOAD"] = True

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
    abort(404)

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