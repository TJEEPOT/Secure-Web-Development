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

from flask import Flask, g, render_template, redirect, request, session, url_for

app = Flask(__name__)
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
        if 'userid' in session:
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
    query = db.get_posts(cid)

    def fix(item):
        item['date'] = datetime.datetime.fromtimestamp(item['date']).strftime('%Y-%m-%d %H:%M')
        return item

    context = request.context
    context['posts'] = map(fix, db.query_db(query))
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
        return redirect(url_for('index'))
    else:
        # Return incorrect details
        return redirect(url_for('login_fail', error='Incorrect Login Details'))


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
    app.run()
