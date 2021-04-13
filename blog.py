# !/usr/bin/env python
# -*- coding: utf-8 -*-

""" Functions for the Flask server
File    : blog.py
Date    : Thursday 25 March 2021
Desc.   : Handles functions for starting up the flask server and site functionality
History : 25/03/2021 - v1.0 - Load basic project file.
"""

__author__ = "Martin Siddons, Chris Sutton, Sam Humphreys, Steven Diep"
__copyright__ = "Copyright 2021, CMP-UG4"
__credits__ = ["Martin Siddons", "Chris Sutton", "Sam Humphreys", "Steven Diep"]
__version__ = "1.0"
__email__ = "gny17hvu@uea.ac.uk"
__status__ = "Development"  # or "Production"

import datetime
import re
import secrets
import string
from functools import wraps

from flask import Flask, g, render_template, redirect, request, session, url_for, flash

import db
import emailer
import validation

app = Flask(__name__)
host = "127.0.0.1"
port = "5000"
# TODO: This will need to go into memory in the future. -MS
# CS: Generated with os.urandom(16)
app.secret_key = "b/n/x0c/x15@/xe2_xf2r#kt/xa1lMf/xf0G"
# CS: Session lasts a week
app.permanent_session_lifetime = datetime.timedelta(days=7)


# TODO: Rewrite for this comes under session token stuff (issue 28/31) -MS
def std_context(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        context = {}
        request.context = context
        if 'validated' in session:
            context['loggedin'] = True
            context['username'] = session['username']
        else:
            context['loggedin'] = False
        return f(*args, **kwargs)

    return wrapper


# I believe this remains here for Flask reasons -MS
@app.teardown_appcontext
def close_connection(exception):
    database = getattr(g, '_database', None)
    if database is not None:
        database.close()


@app.route('/')
@std_context
def index():
    posts = db.get_all_posts()

    def fix(item):
        item['date'] = datetime.datetime.fromtimestamp(item['date']).strftime('%Y-%m-%d %H:%M')
        item['content'] = '%s...' % (item['content'][:200])
        return item

    context = request.context
    context['posts'] = map(fix, posts)
    return render_template('blog/index.html', **context)


@app.route('/<uname>/')
@std_context
def users_posts(uname=None):
    cid = db.get_user(uname)
    if cid is None:
        return 'User page not found.'

    def fix(item):
        item['date'] = datetime.datetime.fromtimestamp(item['date']).strftime('%Y-%m-%d %H:%M')
        return item

    cid = cid['userid']
    context = request.context
    context['posts'] = map(fix, db.get_posts(cid))
    return render_template('user_posts.html', **context)


@app.route('/login/', methods=['GET', 'POST'])
@std_context
def login():
    # CS: Capture IP address
    ip_address = request.remote_addr
    # CS: Insert it if it doesn't exist
    db.update_db('INSERT INTO loginattempts (ip) VALUES (?) ON CONFLICT (ip) DO NOTHING', (ip_address,))
    # CS: Get current login attempts
    login_attempts = db.query_db('SELECT attempts FROM loginattempts WHERE ip =?', (ip_address,))[0]['attempts']
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    context = request.context

    if len(username) < 1 and len(password) < 1:
        return render_template('auth/login.html', **context)

    user_id = db.get_login(username, password)
    if user_id is not None:
        session['userid'] = user_id
        session['username'] = username
        uid = session['userid']
        uses_two_factor = db.query_db('SELECT usetwofactor FROM users WHERE userid =?', (uid,))[0]['usetwofactor']
        url = 'index'
        if uses_two_factor:
            #user_email = db.query_db("SELECT email FROM users WHERE userid =?", (uid,))[0]['email']
            user_email = "dsscw2blogacc@gmail.com"  # Debug only (user emails are fake in current db)
            if validation.validate_email(user_email):
                code = ""
                selection = string.ascii_letters
                for x in range(0, 6):
                    code += secrets.choice(selection)   # TODO secrets library used (not sure if allowed)

                db.set_two_factor(uid, str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')), code)
                # Print code to console for debug
                print(db.query_db("SELECT * FROM twofactor WHERE user = ?", (uid,)))
                # TODO This was intended to be reusable by blog.py, creating and destroying is meh
                # following two lines need to be active in real version (disabled for testing to prevent spam)
                #e = emailer.Emailer()
                #e.send_email(user_email, "Two Factor Code", code)

                url = 'verify_code'
            else:
                # user email is invalid THIS SHOULD ONLY HAPPEN WITH THE FAKE TEST USERS
                print(f"User email is invalid: {user_email}")
        two_factor = db.query_db('SELECT usetwofactor, email FROM users WHERE userid =?', (uid,), one=True)
        url = 'index'
        if two_factor['usetwofactor'] == 1:
            url = emailer.send_two_factor(uid, two_factor['email'])
        else:
            session['validated'] = True

        return redirect(url_for(url))
    else:
        # CS: Update loginattempts for this IP
        login_attempts += 1
        db.update_db('UPDATE loginattempts SET attempts =? WHERE ip =?', (login_attempts, ip_address,))
        if login_attempts > 5:
            # CS: Check lockout time for this IP
            lockout_time = db.query_db('SELECT lockouttime FROM loginattempts WHERE ip =?', (ip_address,))[0]['lockouttime']
            if lockout_time is not None:
                lockout_time = datetime.datetime.strptime(lockout_time, '%Y-%m-%d %H:%M:%S.%f')
            current_time = datetime.datetime.now()
            delta = datetime.timedelta(minutes=15)
            if lockout_time is None:
                # CS: Set lockout time to current time
                db.update_db('UPDATE loginattempts SET lockouttime =? WHERE ip =?', (current_time, ip_address,))
                return redirect(url_for('login_fail', error='Too many incorrect login attempts. Login diabled for 15 minutes.'))
            elif current_time - delta <= lockout_time:
                # CS: Set lockout time to current time
                db.update_db('UPDATE loginattempts SET lockouttime =? WHERE ip =?', (current_time, ip_address,))
                return redirect(url_for('login_fail', error='Too many incorrect login attempts. Login diabled for 15 minutes.'))
            else:
                # CS: Reset the attempts for this IP if it's been more than 15 mins
                db.update_db('UPDATE loginattempts SET attempts =? WHERE ip =?', (1, ip_address,))
                return redirect(url_for('login_fail', error='Incorrect Login Details'))
        else:
            # Return incorrect details
            return redirect(url_for('login_fail', error='Incorrect Login Details'))


@app.route("/confirmation/", methods=['GET', 'POST'])
@std_context
def verify_code():
    """ Two-factor authentication via email OTP """
    if request.method == 'GET':
        return render_template('auth/two_factor.html')

    uid = session['userid']
    user_code = re.match(r"^[\w]{6}$", request.form.get('code', ''))  # Alphanumeric + caps, 6 chars

    # check if two-factor code has been given
    if not user_code:
        return render_template('auth/two_factor.html', error='Code is invalid, please try again.')

    # find the two-factor code in the database for this user
    two_factor = db.get_two_factor(uid)

    # if we're out of time, kick them back to the login screen
    def within_time_limit(db_time: datetime.datetime, curr_time: datetime.datetime):
        db_time = datetime.datetime.strptime(db_time, "%Y-%m-%d %H:%M:%S")
        mins = round((curr_time - db_time).total_seconds() / 60)   # Why does timedelta not have a get minutes func!!!!1
        limit = 5  # Max time for codes to work in minutes
        return mins < limit

    original_time = two_factor['timestamp']
    time_now = datetime.datetime.now()
    if not within_time_limit(original_time, time_now):
        return render_template('auth/login_fail.html', error='Code has expired. Please login again')

    # check the given code and fail them if it doesn't match
    attempts_remaining = two_factor['attempts']
    db_code = two_factor['code']

    if user_code.string != db_code:
        # if they're on the last attempt and got it wrong, kick them back to the login. Lockout too, perhaps?
        if attempts_remaining == 1:
            db.del_two_factor(uid)  # remove this 2fa from the db to prevent possible attacks
            return render_template('auth/login_fail.html', error='Too many failed attempts')

        db.tick_down_two_factor_attempts(uid)
        error = f'Incorrect code. Attempts remaining {attempts_remaining - 1}'
        return render_template('auth/two_factor.html', error=error)

    # success
    session['validated'] = True
    db.del_two_factor(uid)  # remove that code from the db since it's been used
    return redirect(url_for('index'))


# I don't think this code needs moving anywhere since I think it's a flask thing. -MS
@app.route('/loginfail/')
@std_context
def login_fail():
    context = request.context
    context['error_msg'] = request.args.get('error', 'Unknown error')
    return render_template('auth/login_fail.html', **context)


# TODO: Review this when doing sessions (Issue 28) -MS
@app.route('/logout/')
def logout():
    session.pop('userid', None)
    session.pop('username', None)
    session.pop('validated', None)
    session.pop('loggedin', None)
    return redirect('/')


@app.route('/create_account/', methods=['GET', 'POST'])
def create_account():
    if request.method == 'GET':
        return render_template('auth/create_account.html')

    name     = request.form.get('name', '')
    email    = request.form.get('email', '')
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    db.add_user(name, email, username, password)
    # TODO: Should probably check here that the insert was a success before sending a confirmation. If the username
    #  exists, it should tell the user, if the email exists, it should email a password recovery to the user -MS
    # send_confirmation_email()

    return render_template('auth/create_account.html', msg='Check your email for confirmation.')


# TODO: Rewrite db stuff (Issue 27) -MS
@app.route('/post/', methods=['GET', 'POST'])
@std_context
def new_post():
    if 'userid' not in session:
        return redirect(url_for('login'))

    userid = session['userid']
    print(userid)
    context = request.context

    if request.method == 'GET':
        return render_template('blog/new_post.html', **context)

    date = datetime.datetime.now().timestamp()
    title = request.form.get('title')
    content = request.form.get('content')

    db.add_post(content, date, title, userid)
    return redirect('/')


# TODO: Rewrite to hide if account exists or not (Issue 25) -MS
@app.route('/reset/', methods=['GET', 'POST'])
def reset():

    email = request.form.get('email', '')
    print(email)

    # TODO this is a duplicate snippet from two factor code generation , refactor somewhere else
    code = ""
    selection = string.ascii_letters
    for x in range(0, 6):
        code += secrets.choice(selection)  # TODO secrets library used (not sure if allowed)

    inserted = db.insert_reset_code(email, str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')), code)

    if inserted:
        # TODO is there a way to generate a link to a page with hostname and port from flask??
        url = f"http://{host}:{port}{url_for('enter_reset')}?email={email}&code={code}"
        print(url)
        #   send email here

        pass
    message = "If this address exists in our system we will send a reset request to you." \
        if email else ""

    return render_template('auth/reset_request.html', message=message)


@app.route('/enter_reset/', methods=['GET', 'POST'])
def enter_reset():
    email = request.args.get('email')
    code = request.args.get('code')
    if not email or not code:
        email = request.form.get('email', '')
        code = request.form.get('code', '')

    print(f'email: {email} code: {code}')

    success = db.validate_reset_code(email, code)

    if success:
        token = db.insert_and_retrieve_reset_token(email, str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        db.delete_reset_code(email)
        return render_template('auth/reset_password.html', email=email, token=token)
    message = ""
    if email or code:
        message = "Invalid email or reset code!"

    return render_template('auth/enter_reset.html', message=message)


@app.route('/reset_password/', methods=['GET', 'POST'])
def reset_password():
    # compare tokens

    email = request.form.get('email', '')
    token_from_form = request.form.get('token', '')
    password = request.form.get('password', '')
    if email and token_from_form and password:
        token_from_db = db.get_reset_token(email)
        if token_from_db == token_from_form:
            password_changed = db.update_password_from_email(email, password)
            if password_changed:
                message = "Your password has been changed! Please login again."
                flash(message)
                return redirect(url_for('login'))
        else:
            message = "Something went wrong with your password reset. Please try again!"
            return redirect('auth/reset_request.html', message=message)
    return render_template('auth/reset_password.html')

# might want to have these link to the user pages too? -MS
@app.route('/search/')
@std_context
def search_page():
    context = request.context
    search = request.args.get('s', '')

    users = db.get_users(search)
    # for user in users:
    context['users'] = users
    context['query'] = search
    return render_template('search_results.html', **context)


if __name__ == '__main__':
    app.run(host, port)
