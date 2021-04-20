# !/usr/bin/env python
# -*- coding: utf-8 -*-

""" Functions for the Flask server
File    : blog.py
Date    : Thursday 25 March 2021
Desc.   : Handles functions for starting up the flask server and site functionality
History : 25/03/2021 - v1.0 - Load basic project file.
          01/04/2021 - v1.1 - Added 2fa system
          04/04/2021 - v1.2 - Added lockout system for login
          06/04/2021 - v1.3 - Adjustments made for validation, moved secret key to EnvVar
"""

__author__ = "Martin Siddons, Chris Sutton, Sam Humphreys, Steven Diep"
__copyright__ = "Copyright 2021, CMP-UG4"
__credits__ = ["Martin Siddons", "Chris Sutton", "Sam Humphreys", "Steven Diep"]
__version__ = "1.3"
__email__ = "gny17hvu@uea.ac.uk"
__status__ = "Development"  # or "Production"

import datetime

import re
from functools import wraps

from flask import Flask, g, render_template, redirect, request, session, url_for

import auth
import db
import emailer

app = Flask(__name__)
auth.configure_app(app)


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

    context = request.context
    context['posts'] = map(fix, db.get_posts(cid))
    return render_template('blog/user_posts.html', **context)


@app.route('/login/', methods=['GET', 'POST'])
@std_context
def login():
    if request.method == 'GET':
        context = request.context
        return render_template('auth/login.html', **context)
    
    # CS: Capture IP address
    ip_address = request.remote_addr  # TODO: Could this be an attack vector (can the user specify this)?
    # CS: Insert it if it doesn't exist
    db.insert_db('INSERT INTO loginattempts (ip) VALUES (?) ON CONFLICT (ip) DO NOTHING', (ip_address,))

    email = request.form.get('email', '')
    password = request.form.get('password', '')
    user_id, username = db.get_login(email, password)
    
    if user_id is not None or username is not None:
        # valid session
        session['userid'] = user_id
        session['username'] = username

        two_factor = db.query_db('SELECT usetwofactor, email FROM users WHERE userid =?', (user_id,), one=True)
        url = 'index'
        if two_factor['usetwofactor'] == 1:
            url = emailer.send_two_factor(user_id, two_factor['email'])
        else:
            session['validated'] = True
        return redirect(url_for(url))
    
    # CS: Update loginattempts for this IP
    login_attempts = db.query_db('SELECT attempts FROM loginattempts WHERE ip =?', (ip_address,), one=True)['attempts']
    login_attempts += 1

    if login_attempts < 5:
        db.update_db('UPDATE loginattempts SET attempts =? WHERE ip =?', (login_attempts, ip_address))
        remaining_logins = 5 - login_attempts
        return redirect(url_for('login_fail', error=f'Incorrect Login Details, {remaining_logins} attempts remaining.'))

    # CS: Check lockout time for this IP
    query = 'SELECT lockouttime FROM loginattempts WHERE ip =?'
    lockout_time = db.query_db(query, (ip_address,), one=True)['lockouttime']
    if lockout_time is not None:
        lockout_time = datetime.datetime.strptime(lockout_time, '%Y-%m-%d %H:%M:%S.%f')
    current_time = datetime.datetime.now()
    delta = datetime.timedelta(minutes=15)
    
    if lockout_time is None or (current_time - delta) <= lockout_time:
        # CS: Set lockout time to current time
        db.update_db('UPDATE loginattempts SET lockouttime =? WHERE ip =?', (current_time, ip_address))
        return redirect(url_for('login_fail', error='Too many login attempts. Login disabled for 15 minutes.'))
    else:
        # CS: Reset the attempts for this IP if it's been more than 15 mins
        db.update_db('UPDATE loginattempts SET attempts =? WHERE ip =?', (1, ip_address))
        return redirect(url_for('login_fail', error='Incorrect Login Details, 4 attempts remaining.'))


@app.route("/confirmation/", methods=['GET', 'POST'])
@std_context
def verify_code():
    """ Two-factor authentication via email OTP """
    if request.method == 'GET':
        return render_template('auth/two_factor.html')

    uid = session['userid']
    code = request.form.get('code', '')
    user_code = re.match(r"^[\w]{6}$", code)  # Alphanumeric + caps, 6 chars

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
    context['error'] = request.args.get('error', 'Unknown error')
    return render_template('auth/login_fail.html', **context)


# TODO: Review this when doing sessions (Issue 28) -MS
@app.route('/logout/')
def logout():
    session.pop('userid', None)
    session.pop('email', None)
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

    error_msg = db.add_user(name, email, username, password)
    if not error_msg:
        # TODO: send_confirmation_email()
        return render_template('auth/create_account.html', msg='Account created. Check your email for confirmation.')

    if error_msg == 'Email exists':  # specific fail case for email existing
        # TODO: send_password_reset_email()
        return render_template('auth/create_account.html', msg='Account created. Check your email for confirmation.')
    if error_msg:
        return render_template('auth/create_account.html', msg=error_msg)


@app.route('/post/', methods=['GET', 'POST'])
@std_context
def new_post():
    if 'userid' not in session:
        return redirect(url_for('login'))

    if request.method == 'GET':
        context = request.context
        return render_template('blog/new_post.html', **context)

    user_id = session['userid']
    date = datetime.datetime.now().timestamp()
    title = request.form.get('title')
    content = request.form.get('content')

    db.add_post(content, date, title, user_id)
    return redirect('/')


# TODO: Rewrite to hide if account exists or not (Issue 25) -MS
@app.route('/reset/', methods=['GET', 'POST'])
@std_context
def reset():
    if request.method == 'GET':
        return render_template('auth/reset_request.html')

    context = request.context
    email = request.form.get('email', '')
    exists = db.get_email(email)
    if not exists:
        return render_template('auth/no_email.html', **context)

    context['email'] = email
    return render_template('auth/sent_reset.html', **context)


@app.route('/search/')
@std_context
def search_page():
    context = request.context
    search = request.args.get('s', '')

    users, validated_search = db.get_users(search)
    # for user in users:
    context['users'] = users
    context['query'] = validated_search
    return render_template('blog/search_results.html', **context)


if __name__ == '__main__':
    app.run()
