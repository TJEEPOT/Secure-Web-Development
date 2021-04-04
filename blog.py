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
from functools import wraps

import db

from flask import Flask, g, render_template, redirect, request, session, url_for

from emailer import send_two_factor

app = Flask(__name__)

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
        two_factor = db.query_db('SELECT usetwofactor, email FROM users WHERE userid =?', (uid,), one=True)
        url = 'index'
        if two_factor['usetwofactor'] == 1:
            url = send_two_factor(uid, two_factor['email'])
        else:
            session['validated'] = True

        return redirect(url_for(url))
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
        print(uid, user_code)
        return render_template('auth/two_factor.html', error='Code is invalid, please try again.')

    # find the two-factor code in the database for this user
    two_factor = db.query_db("SELECT * FROM twofactor WHERE user = ?", (uid,), one=True)

    # if we're out of time, kick them back to the login screen
    def within_time_limit(db_time: datetime.datetime, curr_time: datetime.datetime):
        db_time = datetime.datetime.strptime(db_time, "%Y-%m-%d %H:%M:%S")
        mins = round((time_now - db_time).total_seconds() / 60)   # Why does timedelta not have a get minutes func!!!!1
        limit = 5  # Max time for codes to work in minutes
        return mins < limit

    original_time = two_factor['timestamp']
    time_now = datetime.datetime.now()
    if not within_time_limit(original_time, time_now):
        return render_template('auth/login_fail.html', error='Code has expired. Please login again')

    # check the given code and fail them if it doesn't match
    attempts_remaining = (two_factor['attempts'])
    db_code = db.query_db("SELECT code FROM twofactor WHERE user=?", (uid,), one=True)['code']

    if user_code != db_code:
        # if they're on the last attempt and got it wrong, kick them back to the login. Lockout too, perhaps?
        if attempts_remaining == 1:
            return render_template('auth/login_fail.html', error='Too many failed attempts')

        db.tick_down_two_factor_attempts(uid)
        error = f'Invalid code. Attempts remaining {attempts_remaining - 1}'
        return render_template('auth/two_factor.html', error=error)

    # success
    session['validated'] = True
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
@std_context
def reset():
    context = request.context

    email = request.form.get('email', '')
    if email == '':
        return render_template('auth/reset_request.html')

    exists = db.get_email(email)
    if len(exists) < 1:
        return render_template('auth/no_email.html', **context)
    else:
        context['email'] = email
        return render_template('auth/sent_reset.html', **context)


# TODO: Rewrite db stuff (Issue 27) -MS
# might want to have these link to the user pages too?
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
    app.run()
