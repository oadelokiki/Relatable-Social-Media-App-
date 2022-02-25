import base64
import datetime
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from modules import login_required, apology, allowed_file
from flask import Flask, make_response
import os
from flask import Flask, flash,url_for
from werkzeug.utils import secure_filename
from datetime import datetime
import random
from modules import *

UPLOAD_FOLDER = 'static/uploaded/'

app = Flask(__name__)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///relatable.db")

# Make sure API key is set


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        if not (request.form.get("password") == request.form.get("confirmation")):
            return apology("passwords must match", 403)

        if len(db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))) > 0:
            return apology("This username is taken. Please try another username.", 403)

        else:
            db.execute("INSERT into users (username, hash) VALUES(?, ?)", request.form.get("username"), generate_password_hash(request.form.get("password")))
            return render_template("login.html")
    else:
        return render_template("register.html")

app.route("logout", methods=["GET"])
@login_required
def login():
    session["user_id"] = None
    return redirect("/")

@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)


        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return flash("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["user_id"]
        return redirect("/")
    else:
        return render_template("login.html")


@app.route("/friends", methods=["GET", "POST"])
@login_required
def friends():
    postlist = []
    images =[]

    generallist = db.execute("SELECT destination FROM relations WHERE source = ? AND relation_type = 'friends';", session["user_id"])

    for x in range(0, len(generallist)):

        templist = (db.execute("SELECT * FROM posts WHERE user_id = ?", generallist[x]["destination"]))
        for y in range(0, len(templist)):
            postlist.append(templist[y])

    random.shuffle(postlist)

    rightrange = len(postlist)



    if (request.method == "POST"):
        handlepost()
        return render_template("index.html", postlist = postlist, rightrange = rightrange)

    else:
        if len(postlist) == 0:
            flash("It appears you haven't been too Relatable! It's time to make some connections!")

        return render_template("index.html", postlist = postlist, rightrange = rightrange)

@app.route("/family", methods=["GET", "POST"])
@login_required
def family():
    postlist = []
    images =[]

    generallist = db.execute("SELECT destination FROM relations WHERE source = ? AND relation_type = 'family';", session["user_id"])

    for x in range(0, len(generallist)):

        templist = (db.execute("SELECT * FROM posts WHERE user_id = ?", generallist[x]["destination"]))
        for y in range(0, len(templist)):
            postlist.append(templist[y])

    random.shuffle(postlist)

    rightrange = len(postlist)



    if (request.method == "POST"):
        handlepost()
        return render_template("index.html", postlist = postlist, rightrange = rightrange)

    else:
        if len(postlist) == 0:
            flash("It appears you haven't been too Relatable! It's time to make some connections!")

        return render_template("index.html", postlist = postlist, rightrange = rightrange)

@app.route("/", methods=["GET", "POST"])
@login_required
def index():

    postlist = []
    images =[]

    generallist = db.execute("SELECT destination FROM relations WHERE source = ? AND relation_type = 'general';", session["user_id"])

    for x in range(0, len(generallist)):

        templist = (db.execute("SELECT * FROM posts WHERE user_id = ?", generallist[x]["destination"]))
        for y in range(0, len(templist)):
            postlist.append(templist[y])

    random.shuffle(postlist)

    rightrange = len(postlist)



    if (request.method == "POST"):
        handlepost()
        return render_template("index.html", postlist = postlist, rightrange = rightrange)

    else:
        if len(postlist) == 0:
            flash("It appears you haven't been too Relatable! It's time to make some connections!")

        return render_template("index.html", postlist = postlist, rightrange = rightrange)

@app.route('/display/<filename>')
@login_required
def display_image(filename):
	#print('display_image filename: ' + filename)
	return redirect(url_for('static', filename='uploaded/' + filename), code=301)

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profiles():
    method = request.method

    if request.method == "POST":

        if request.form.get("addform"):
            return redirect('/add')

        postlist = []


        postlist = db.execute("SELECT * FROM posts WHERE user_id = ?", db.execute("SELECT user_id FROM users WHERE username= ?", request.form.get("username"))[0]["user_id"])
        for x in range(0,  len(postlist)):
            postlist[x]["user_id"] = db.execute("SELECT username FROM users WHERE user_id = ?", postlist[x]["user_id"])[0]["username"]
        random.shuffle(postlist)

        rightrange = len(postlist)
        return render_template("profile.html", postlist = postlist, rightrange = rightrange, method = method)
    else:

        return render_template("profile.html", method = method)




@app.route("/add", methods=["POST"])
@login_required
def add():
    if request.method == "POST":


        if request.form.get('destination'):
            useridproper = db.execute("SELECT user_id FROM users WHERE username = ?", request.form.get('destination'))[0]["user_id"]

            if db.execute("SELECT * from notifications where origin_id = ? and destination_id = ? and channel = ?", useridproper, session["user_id"], request.form.get("channel")):

                db.execute("INSERT INTO relations(source, destination, relation_type) VALUES(?,?,?)", useridproper, session["user_id"], request.form.get("channel"))

                db.execute("INSERT INTO relations(source, destination, relation_type) VALUES(?,?,?)", session["user_id"], useridproper, request.form.get("channel"))

                flash("User " + request.form.get("destination") + " added to " + request.form.get("channel"))

                return redirect("/")
            if db.execute("SELECT username FROM users WHERE username = ?", request.form.get('destination'))[0]["username"]:



                db.execute("INSERT INTO notifications(notification_message, origin_id, destination_id, notification_type, channel) VALUES(?, ?, ?, ?, ?)",

                ("User " + db.execute("SELECT username FROM users WHERE user_id = ?", session["user_id"])[0]["username"] + " has requested to add you to their" + request.form.get("channel")
                ),

                session["user_id"],

                db.execute("SELECT user_id FROM users WHERE username = ?", request.form.get('destination'))[0]["user_id"],

                "add",

                request.form.get("channel")

                )

                return flash("Request Sent!")

            else:
                return flash("User Not Found")

        else:
            flash("Please Specify A User")
            return redirect("/")
    else:
        return redirect("/")

#helper functions
def handlepost():
    """Implement post creation mechanics with specific channel selection"""
    """Defualt post method should be into the general channel"""


            # check if the post request has the file part
    if 'file' not in request.files:
        flash('No File Part')
        return redirect(request.url)

    file = request.files['file']

        # If the user does not select a file, the browser submits an
        # empty file without a filename.

    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    filepath = filename

    usertext= request.form.get("usertext")


    #channel is temporary and should be collected via form selector
    channel = request.form.get("channel")
    timeindex = datetime.now()

    db.execute("INSERT INTO posts (user_id, photolocation, text, channel, date_and_time) VALUES(?,?,?,?,?);",session["user_id"],filepath, usertext, channel, timeindex)
    flash("Post Created")



