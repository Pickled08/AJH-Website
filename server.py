#Imports
from flask import Flask
from threading import Thread
from flask import render_template

#Setup Variables
app = Flask(__name__)
app = Flask(__name__, template_folder="site_files")
app.config["TEMPLATES_AUTO_RELOAD"] = True

#Home Page
@app.route("/")
def index():
    return render_template("index.html")

#404 Error
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

#Functions to run the server
def run():
  app.run(host='0.0.0.0',port=8080)
  
def start():
    t = Thread(target=run)
    t.start()