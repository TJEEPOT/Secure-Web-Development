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

import sqlite3
from functools import wraps

from flask import Flask, g, render_template, redirect, request, session, url_for


from functools import wraps
import auth
import db
import emailer
import validation

from flask import Flask, g, render_template, redirect, request, session, url_for

app = Flask(__name__)
app.secret_key = 'thisisabadsecretkey'  # KEK


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


@app.route("/")
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


@app.route("/<uname>/")
@std_context
def users_posts(uname=None):
    cid = db.get_user(uname)
    if len(cid) < 1:
        return 'User page not found.'

    cid = cid[0]['userid']
    query = 'SELECT date,title,content FROM posts WHERE creator=? ORDER BY date DESC'
    arg = (cid,)
    def fix(item):
        item['date'] = datetime.datetime.fromtimestamp(item['date']).strftime('%Y-%m-%d %H:%M')
        return item

    context = request.context
    context['posts'] = map(fix, db.query_db(query, arg))
    return render_template('user_posts.html', **context)


@app.route("/login/", methods=['GET', 'POST'])
@std_context
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    context = request.context

    if len(username) < 1 and len(password) < 1:
        return render_template('auth/login.html', **context)

    account = auth.authenticate_user(username, password)
    if account is not None:
        session['userid'] = account[0]['userid']
        session['username'] = username
        uid = session['userid']
        uses_two_factor = db.query_db('SELECT usetwofactor FROM users WHERE userid =?', (uid,))[0]['usetwofactor']
        url = 'index'
        if uses_two_factor:
            #user_email = db.query_db("SELECT email FROM users WHERE userid =?", (uid,))[0]['email']
            user_email = "dsscw2blogacc@gmail.com"  # Debug only (user emails are fake in current db)
            if validation.validate_email(user_email):
                code = auth.generate_two_factor_code()
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


        else:
            session['validated'] = True

        return redirect(url_for(url))
    else:
        # Return incorrect details
        return redirect(url_for('login_fail', error='Incorrect Login Details'))


@app.route("/confirmation/", methods=['GET', 'POST'])
@std_context
def verify_code():
    # Function for two factor authentication
    uid = session['userid']
    user_code = validation.validate_two_factor(request.form.get('code', ''))

    def within_time_limit(db_time: datetime.datetime, curr_time: datetime.datetime):
        db_time = datetime.datetime.strptime(db_time, "%Y-%m-%d %H:%M:%S")
        mins = round((time_now - db_time).total_seconds() / 60)   # Why does timedelta not have a get minutes func!!!!1
        limit = 5  # Max time for codes to work in minutes
        return mins < limit

    if user_code:
        row = db.query_db("SELECT * FROM twofactor WHERE user = ?", (uid,))
        attempts_remaining = (row[0]['attempts'])-1
        original_time = row[0]['timestamp']
        time_now = datetime.datetime.now()

        if attempts_remaining > 0:
            if within_time_limit(original_time, time_now):
                db_code = db.query_db("SELECT code FROM twofactor WHERE user=?", (uid,))[0]['code']
                if user_code == db_code:
                    # success
                    session['validated'] = True
                    return redirect(url_for('index'))
                else:
                    # fail
                    db.tick_down_two_factor_attempts(uid)
                    return render_template('auth/two_factor.html',
                                           message=f'Invalid code. Attempts remaining {attempts_remaining}')
            else:
                return render_template('auth/login_fail.html', error='Code has expired. Please login again')
        else:
            return render_template('auth/login_fail.html', error='Too many failed attempts')
    return render_template('auth/two_factor.html', error='Code has expired or is invalid')


# I don't think this code needs moving anywhere since I think it's a flask thing. -MS
@app.route("/loginfail/")
@std_context
def login_fail():
    context = request.context
    context['error_msg'] = request.args.get('error', 'Unknown error')
    return render_template('auth/login_fail.html', **context)


# TODO: Review this when doing sessions (Issue 28) -MS
@app.route("/logout/")
def logout():
    session.pop('userid', None)
    session.pop('username', None)
    session.pop('validated', None)
    session.pop('loggedin', None)
    return redirect('/')


# TODO: Rewrite db stuff (Issue 27) -MS
@app.route("/post/", methods=['GET', 'POST'])
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

    query = db.add_post(content, date, title, userid)
    db.query_db(query)
    db.get_db().commit()
    return redirect('/')


# TODO: Rewrite to hide if account exists or not (Issue 25) -MS
@app.route("/reset/", methods=['GET', 'POST'])
@std_context
def reset():
    context = request.context

    email = request.form.get('email', '')
    if email == '':
        return render_template('auth/reset_request.html')

    query = db.get_email(email)
    exists = db.query_db(query)
    if len(exists) < 1:
        return render_template('auth/no_email.html', **context)
    else:
        context['email'] = email
        return render_template('auth/sent_reset.html', **context)


# TODO: Rewrite db stuff (Issue 27) -MS
# might want to have these link to the user pages too?
@app.route("/search/")
@std_context
def search_page():
    context = request.context
    search = request.args.get('s', '')

    query = db.get_users(search)
    users = db.query_db(query)
    # for user in users:
    context['users'] = users
    context['query'] = search
    return render_template('search_results.html', **context)


# TODO: might want to remove this (Issue 4) -MS
@app.route("/resetdb/<token>")
def reset_db(token=None):
    if token == 'secret42':
        import create_db
        create_db.delete_db()
        create_db.create()
        return 'Database reset'
    else:
        return 'Nope', 401


if __name__ == '__main__':
    e = emailer.Emailer()
    app.run()
