import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    stock_symbols = db.execute("SELECT DISTINCT symbol FROM purchases WHERE user_id = ?", session["user_id"])
    stock_list = []
    user_info = {}
    user_info["total"] = 0
    for stock in stock_symbols:
        dict = {}
        stock = stock["symbol"]
        shares = db.execute("SELECT SUM(shares) FROM purchases WHERE user_id = ? AND symbol = ?",
                            session["user_id"], stock)[0]["SUM(shares)"]
        info = lookup(stock)
        dict["symbol"] = stock
        dict["name"] = info["name"]
        dict["shares"] = shares
        dict["price"] = usd(info["price"])
        dict["total"] = usd(info["price"] * shares)
        user_info["total"] += info["price"] * shares
        stock_list.append(dict)
    _cash = db.execute("SELECT cash FROM users WHERE id=?", session["user_id"])[0]["cash"]
    user_total = usd(_cash + user_info["total"])
    user_info["cash"] = usd(_cash)
    user_info["total"] = usd(user_info["total"])

    return render_template("index.html",
                           stock_list=stock_list,
                           user_info=user_info,
                           user_total=user_total
                           )


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        shares = request.form.get("shares")
        if not shares.isdigit():
            return apology("Invalid.")
        shares = float(shares)
        if not shares > 0:
            return apology("Invalid shares.")
        if stock := lookup(symbol):
            cash = float(db.execute("SELECT cash FROM users WHERE id=?", session["user_id"])[0]["cash"])
            price_float = float(stock["price"]) * shares
            if cash >= price_float:
                db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", price_float, session["user_id"])
                db.execute("INSERT INTO purchases (user_id, symbol, price, shares) VALUES (?, ?, ?, ?)",
                           session["user_id"], stock["symbol"], stock["price"], shares)
            else:
                return apology("Insufficient balance")
        else:
            return apology("Invalid stock.")
        return redirect("/")
    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history_list = db.execute("SELECT * FROM purchases WHERE user_id = ?", session["user_id"])[::-1]
    for history in history_list:
        history["price"] = usd(history["price"])
    return render_template("history.html", history_list=history_list)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
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
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if stock := lookup(symbol):
            price = usd(stock["price"])
            return render_template("quoted.html",
                                   stock=stock,
                                   price=price,
                                   )
        return apology("Couldn't find stock.")
    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # TODO: add user to database if matches qualifications.
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        users = db.execute("SELECT username FROM users")
        error_msg = ""

        # Check user requirements and add an error message.
        if not 3 <= len(username) <= 16:
            if len(username) < 3:
                error_msg = "Username is too short"
            elif len(username) > 16:
                error_msg = "Username is too long"
        elif not password == confirmation:
            error_msg = "Passwords do not match."
        elif not 4 <= len(password):
            error_msg = "Password is too short."
        elif username.lower() in [users[i]["username"].lower() for i in range(len(users))]:
            error_msg = "Username is already taken."

        if error_msg:
            return apology(error_msg)

        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, generate_password_hash(password))
        return redirect("/login")

    else:  # request.method is "GET"
        # TODO: create register form for the user
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        try:
            symbol = request.form.get("symbol").upper()
            shares_to_sell = float(request.form.get("shares"))
        except ValueError:
            return apology("Invalid.")
        if shares_to_sell <= 0:
            return apology("Invalid shares.")
        if stock := lookup(symbol):
            shares_owned = db.execute("SELECT SUM(shares) FROM purchases WHERE user_id = ? AND symbol = ? ",
                                      session["user_id"], stock["symbol"])[0]["SUM(shares)"]
            if not shares_owned or shares_owned <= 0:
                return apology("Unowned stock")
            if shares_owned > 0 and shares_owned >= shares_to_sell:  # sell stocks
                db.execute("INSERT INTO purchases (user_id, symbol, price, shares) VALUES (?, ?, ?, ?)",
                           session["user_id"], stock["symbol"], stock["price"], -shares_to_sell)
                sold_value = shares_to_sell * stock["price"]
                db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", sold_value, session["user_id"])
            else:
                return apology("Insufficient stock balance")
        else:
            return apology("Invalid stock.")
        return redirect("/")

    stocks = db.execute("SELECT DISTINCT symbol FROM purchases WHERE user_id = ?", session["user_id"])
    for stock in stocks:
        tmp = db.execute("SELECT SUM(shares) FROM purchases WHERE user_id = ? AND symbol = ?",
                         session["user_id"], stock["symbol"])[0]["SUM(shares)"]
        stock["sum"] = tmp
    return render_template("sell.html", stocks=stocks)

