#Imports
from flask import Flask
from threading import Thread
from flask import render_template

#Setup Variables
app = Flask(__name__)
app = Flask(__name__, template_folder="site_files")

@app.route("/")
def index():
    return render_template("index.html")

#Functions to run the server
def run():
  app.run(host='0.0.0.0',port=8080)
  
def start():
    t = Thread(target=run)
    t.start()
