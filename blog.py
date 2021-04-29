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
import os
import re
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, g, render_template, redirect, request, session, url_for, flash

import auth
import blowfish
import db
import emailer
import string
import random

app = Flask(__name__)
host = "127.0.0.1"
port = "5000"
load_dotenv(override=True)
app.secret_key = bytes(os.environ["UG_4_SECRET_KEY"], "utf-8").decode('unicode_escape')
app.permanent_session_lifetime = datetime.timedelta(days=1)  # CS: Session lasts a day


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


@app.route('/<uname>/', methods=['GET', 'POST'])
@std_context
def users_posts(uname=None):
    if request.method == 'GET':
        cid = db.get_user(uname)
        if cid is None:
            return 'User page not found.'

        def fix(item):
            item['date'] = datetime.datetime.fromtimestamp(item['date']).strftime('%Y-%m-%d %H:%M')
            return item

        context = request.context
        context['posts'] = map(fix, db.get_posts(cid))
        # CS: if the currently logged in user is viewing their own posts
        if session:
            if session['userid'] == cid:
                context['uname'] = uname
                context['email'] = db.query_db('SELECT email FROM users WHERE userid=?', (cid,), one=True)['email']
                context['twofactor'] = db.query_db('SELECT usetwofactor FROM users WHERE userid =?', (cid,), one=True)['usetwofactor']
        return render_template('user_posts.html', **context)
    else:
        cid = session['userid']
        new_username = request.form.get('username', '')
        new_email = request.form.get('email', '')
        new_usetwofactor = request.form.get('twofactor', 0)
        if new_usetwofactor == 'on':
            new_usetwofactor = 1
        else:
            new_usetwofactor = 0

        csrftoken = request.form.get('csrftoken')
        block_cipher = blowfish.BlowyFishy(app.secret_key)
        mode_ctr = blowfish.CTR(block_cipher, session['nonce'])
        decrypted = mode_ctr.ctr_decryption(csrftoken)
        if decrypted != app.secret_key:
            error_msg = 'CSRF token invalid.'
        else:
            error_msg = db.update_user(cid, new_username, new_email, new_usetwofactor)
        if not error_msg:
            session['username'] = new_username
            return redirect(url_for('users_posts', uname=new_username))
        else:
            return redirect(url_for('users_posts', uname=session['username'], msg=error_msg))


@app.route('/login/', methods=['GET', 'POST'])
@std_context
def login():
    if request.method == 'GET':
        context = request.context
        return render_template('auth/login.html', **context)

    # CS: Capture IP address
    ip_address = request.remote_addr
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
            key = app.secret_key
            block_cipher = blowfish.BlowyFishy(key)
            session['nonce'] = blowfish.get_nonce()
            mode_ctr = blowfish.CTR(block_cipher, session['nonce'])
            cipher = mode_ctr.ctr_encryption(key)
            session['CSRFtoken'] = cipher
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
        mins = round((curr_time - db_time).total_seconds() / 60)  # Why does timedelta not have a get minutes func!!!!1
        limit = 5  # Max time for codes to work in minutes
        return mins < limit

    original_time = two_factor['timestamp']
    if not db.within_time_limit(original_time):
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
    key = app.secret_key
    block_cipher = blowfish.BlowyFishy(key)
    session['nonce'] = blowfish.get_nonce()
    mode_ctr = blowfish.CTR(block_cipher, session['nonce'])
    cipher = mode_ctr.ctr_encryption(key)
    session['CSRFtoken'] = cipher
    return redirect(url_for('index'))


# I don't think this code needs moving anywhere since I think it's a flask thing. -MS
@app.route('/loginfail/')
@std_context
def login_fail():
    context = request.context
    context['error'] = request.args.get('error', 'Unknown error')
    return render_template('auth/login_fail.html', **context)


@app.route('/logout/')
def logout():
    session.pop('userid', None)
    session.pop('email', None)
    session.pop('validated', None)
    session.pop('loggedin', None)
    session.pop('CSRFtoken', None)
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
        emailer.send_account_confirmation(email, name)
        return render_template('auth/create_account.html', msg='Account created. Check your email for confirmation.')

    if error_msg == 'Email exists':  # specific fail case for email existing
        code = auth.generate_code()
        inserted = db.insert_reset_code(email, str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')), code)
        if inserted:
            url = f"http://{host}:{port}{url_for('enter_reset')}?email={email}&code={code}"
            emailer.send_reset_link(email, url)
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
    csrftoken = request.form.get('csrftoken')
    block_cipher = blowfish.BlowyFishy(app.secret_key)
    mode_ctr = blowfish.CTR(block_cipher, session['nonce'])
    decrypted = mode_ctr.ctr_decryption(csrftoken)
    error_msg = ''
    if decrypted != app.secret_key:
        error_msg = 'CSRF token invalid.'
    else:
        db.add_post(content, date, title, user_id)
    db.add_post(content, date, title, user_id)
    return redirect('/')


@app.route('/reset/', methods=['GET', 'POST'])
@std_context
def reset():
    if request.method == 'GET':
        return render_template('auth/reset_request.html')

    email = request.form.get('email', '')
    code = auth.generate_code()
    inserted = db.insert_reset_code(email, str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')), code)

    if inserted:
        # TODO is there a way to generate a link to a page with hostname and port from flask??
        url = f"http://{host}:{port}{url_for('enter_reset')}?email={email}&code={code}"
        emailer.send_reset_link(email, url)

    message = "If this address exists in our system we will send a reset request to you."
    flash(message)
    return render_template('auth/reset_request.html')


@app.route('/enter_reset/', methods=['GET', 'POST'])
def enter_reset():
    email = request.args.get('email')
    code = request.args.get('code')
    if not email or not code:
        email = request.form.get('email', '')
        code = request.form.get('code', '')

    print(f'email: {email} code: {code}')
    success = db.validate_reset_code(email, code)
    within_time = False
    if email:
        within_time = db.user_reset_code_within_time_limit(db.get_user_id_from_email(email))
    message = ""
    if success:
        if within_time:
            token = db.insert_and_retrieve_reset_token(email, str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            return render_template('auth/reset_password.html', email=email, token=token)
        else:
            message = "That code has expired please start a new reset request!"
        db.delete_reset_code(email)
    if within_time and (email or code):
        message = "Invalid email or reset code!"
    flash(message)
    return render_template('auth/enter_reset.html')


@app.route('/reset_password/', methods=['GET', 'POST'])
def reset_password():
    # compare tokens

    email = request.form.get('email', '')
    token_from_form = request.form.get('token', '')
    password = request.form.get('password', '')

    if email and token_from_form and password:
        token_from_db = db.get_reset_token(email)
        if token_from_db == token_from_form:
            is_weak = db.is_weak_password(password)
            if is_weak:
                message = "That password is known to be weak, please try another."
                flash(message)
            else:
                password_changed = db.update_password_from_email(email, password)
                if password_changed:
                    message = "Your password has been changed! Please login again."
                    flash(message)
                    return redirect(url_for('login'))
        else:
            message = "Something went wrong with your password reset. Please try again!"
            flash(message)
            return redirect(url_for('reset'))
    return render_template('auth/reset_password.html')


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

@app.route('/admin/')
@std_context
def admin_page():
    return redirect("https://www.youtube.com/watch?v=dQw4w9WgXcQ")
if __name__ == '__main__':
    app.run()
