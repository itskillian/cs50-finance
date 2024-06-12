import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
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


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/", methods=['GET', 'POST'])
@login_required
def index():
    """Show portfolio of stocks"""

    # gather table data from portfolio; symbol, total_shares
    try:
        stocks = db.execute(
            'SELECT symbol, total_shares, avg_price, total_cost FROM portfolio WHERE userID = ? AND total_shares > 0',
            session['user_id']
        )
    except (RuntimeError, ValueError, KeyError):
        return apology('something went wrong')
    
    try:
        user = db.execute(
            'SELECT cash FROM users WHERE id = ?', session['user_id']
        )[0]
    except (RuntimeError, ValueError, KeyError):
        return apology('something went wrong')
    else:
        user['total_assets'] = 0
        user['grand_total'] = 0

    # fill in remaining fields using API call to Yahoo
    for stock in stocks:
        stock['share_price'] = lookup(stock['symbol'])['price']
        stock['total_value'] = stock['share_price'] * stock['total_shares']
        stock['profit_loss'] = stock['total_value'] - stock['total_cost']
        user['total_assets'] = user['total_assets'] + stock['total_value']

    user['grand_total'] = user['cash'] + user['total_assets']

    return render_template('index.html', stocks=stocks, user=user)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # user reached route via POST (submit form)
    if request.method == 'POST':

        # validate submission
        transaction_type = 'BUY'
        symbol = request.form.get('symbol').upper()
        shares = request.form.get('shares')
        quote = lookup(symbol)

        try:
            shares = float(shares)
        except (TypeError, ValueError) as e:
            return apology('invalid input')

        if shares < 1 or shares % 1 != 0:
            return apology('please enter a valid number')
        if not symbol:
            return apology('search cannot be blank')
        elif quote == None:
            return apology('stock symbol not found')

        # check stock price
        price = (lookup(symbol)['price'])
        total = price * shares

        # sql begin transaction
        db.execute('BEGIN TRANSACTION')

        # check user balance
        try:
            cash = db.execute(
                'SELECT cash FROM users WHERE id = ?', session['user_id']
            )[0]['cash']
            if cash <= total:
                db.execute('ROLLBACK')
                return apology('you dont have enough money WOMP')
        except (RuntimeError, ValueError, KeyError):
            db.execute('ROLLBACK')
            return apology('something went wrong')

        # buy the shares
        try:
            db.execute(
                'UPDATE users SET cash = cash - ? WHERE id = ?',
                total, session['user_id']
            )
            db.execute(
                'INSERT INTO transactions (userID, symbol, shares, transactionType, price, total, timestamp) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)',
                session['user_id'], symbol, shares, transaction_type, price, total
            )
        except (RuntimeError, ValueError, KeyError):
            db.execute('ROLLBACK')
            return apology('something went wrong')
        except:
            db.execute('ROLLBACK')
            return apology('something went very wrong')

        # update portfolio table
        try:
            # attempt to insert new row
            db.execute(
                'INSERT INTO portfolio (userID, symbol, total_shares, avg_price, total_cost) VALUES (?, ?, ?, ?, ?)',
                session['user_id'], symbol, shares, price, total
            )
        # if UNIQUE symbol row already exists, ValueError thrown, UPDATE existing instead
        except ValueError:
            try:
                db.execute(
                    'UPDATE portfolio SET total_shares = total_shares + ?, total_cost = total_cost + ? WHERE userID = ? AND symbol = ?',
                    shares, total, session['user_id'], symbol
                )
                # update avg_price using new values from previous line
                db.execute('UPDATE portfolio SET avg_price = total_cost / total_shares')
            except:
                db.execute('ROLLBACK')
                return apology('something went wrong')
        # else if other exceptions occur
        except (RuntimeError, KeyError):
            db.execute('ROLLBACK')
            return apology('something went wrong')

        # commit transaction
        db.execute('COMMIT')

        # Redirect user to home page
        return redirect("/")

    # user reached route via GET (link or redirect)
    else:
        try:
            user = db.execute(
            'SELECT cash FROM users WHERE id = ?', session['user_id']
            )[0]
        except RuntimeError:
            return apology('something went wrong')
        
        return render_template('buy.html', user=user)


@app.route("/history", methods=['GET'])
@login_required
def history():
    """Show history of transactions"""
    try:
        stocks = db.execute(
            'SELECT symbol, shares, price, total, transactionType, timestamp FROM transactions WHERE userID = ? ORDER BY symbol, timestamp',
            session['user_id']
        )
    except RuntimeError:
        return apology('something went wrong')
    
    try:
        user = db.execute(
        'SELECT cash FROM users WHERE id = ?', session['user_id']
        )[0]
    except RuntimeError:
        return apology('something went wrong')
    
    return render_template('history.html', stocks=stocks, user=user)


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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?",
            request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
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

    # user reached route via POST (submit form)
    if request.method == 'POST':

        # validate submission
        symbol = request.form.get('symbol')
        if not symbol:
            return apology('please enter a stock symbol')

        # query API validate symbol
        quote = (lookup(symbol))
        if quote is None:
            return apology('please enter a valid stock symbol')
        else:
            try:
                user = db.execute(
                    'SELECT cash FROM users WHERE id = ?', session['user_id']
                )[0]
            except RuntimeError:
                return apology('something went wrong')
            
            return render_template('quoted.html', symbol=symbol, quote=quote, user=user)

    # user reached route via GET (link or redirect)
    else:
        try:
            user = db.execute(
                'SELECT cash FROM users WHERE id = ?', session['user_id']
            )[0]
        except RuntimeError:
            return apology('something went wrong')
        
        return render_template('quote.html', user=user)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == 'POST':

        # TODO validate submission
        username = request.form.get('username')
        password = request.form.get('password')
        confirmation = request.form.get('confirmation')
        if not username:
            return apology('must provide username')
        elif not password or not confirmation:
            return apology('must provide password and confirmation')
        elif password != confirmation:
            return apology('password and confirmation must match')

        # generate password hash
        hash = generate_password_hash(password)

        try:
            db.execute(
                'INSERT INTO users (username, hash) VALUES (?, ?)',
                username, hash
            )
        except ValueError:
            return apology('username already exists')

        # redirect to login.html
        return redirect('/')

    else:
        return render_template('register.html')


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # if user reached route via POST (sell now button)
    if request.method == 'POST':

        # validate submission
        transaction_type = 'SELL'
        symbol = request.form.get('symbol').upper()
        shares = request.form.get('shares')
        quote = lookup(symbol)
        try:
            shares = float(shares)
        except (TypeError, ValueError) as e:
            return apology('invalid input')
        if shares < 1 or shares % 1 != 0:
            return apology('please enter a valid number')
        if not symbol:
            return apology('search cannot be blank')
        elif quote == None:
            return apology('invalid stock symbol')

        # check stock price
        price = (lookup(symbol)['price'])
        total = price * shares

        # sql begin transaction
        db.execute('BEGIN TRANSACTION')

        # check user has enough shares
        total_shares = db.execute(
            'SELECT total_shares FROM portfolio WHERE userID = ? AND symbol = ?',
            session['user_id'], symbol
        )[0]['total_shares']

        if total_shares < shares:
            db.execute('ROLLBACK')
            return apology('you dont have enough shares')

        # sell the shares
        try:
            db.execute(
                'UPDATE users SET cash = cash + ? WHERE id = ?',
                total, session['user_id']
            )
            db.execute(
                'INSERT INTO transactions (userID, symbol, shares, transactionType, price, total, timestamp) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)',
                session['user_id'], symbol, shares, transaction_type, price, total
            )
        except (RuntimeError, ValueError, KeyError) as e:
            db.execute('ROLLBACK')
            return apology('Exception Occured')

        # if selling all shares, delete row from table
        if total_shares == shares:
            try:
                db.execute(
                    'DELETE FROM portfolio WHERE userID = ? AND symbol = ?',
                    session['user_id'], symbol
                )
            except:
                db.execute('ROLLBACK')
        # update portfolio table
        else:
            try:
                db.execute(
                    'UPDATE portfolio SET total_shares = total_shares - ?, total_cost = total_cost - ? WHERE userID = ? AND symbol = ?',
                    shares, total, session['user_id'], symbol
                )
                # update avg_price using new values from previous line
                db.execute('UPDATE portfolio SET avg_price = total_cost / total_shares')
            except (RuntimeError, ValueError, KeyError) as e:
                db.execute('ROLLBACK')
                return apology('something went wrong')

        # commit transaction
        db.execute('COMMIT')

        # Redirect user to home page
        return redirect("/")

    # user reached route via GET (link or redirect)
    else:
        # populate html table
        stocks = db.execute(
            'SELECT symbol, total_shares, avg_price, total_cost FROM portfolio WHERE userID = ? AND total_shares > 0',
            session['user_id']
        )
        for stock in stocks:
            stock['share_price'] = lookup(stock['symbol'])['price']
            stock['total_value'] = stock['share_price'] * stock['total_shares']
            stock['profit_loss'] = stock['total_value'] - stock['total_cost']
        
        try:
            user = db.execute(
            'SELECT cash FROM users WHERE id = ?', session['user_id']
            )[0]
        except RuntimeError:
            return apology('something went wrong')

        return render_template('sell.html', stocks=stocks, user=user)
