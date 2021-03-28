# !/usr/bin/env python
# -*- coding: utf-8 -*-

""" Functions for the Flask server
File    : blog.py
Date    : Thursday 25 March 2021
Desc.   : Handles functions for starting up the flask server and site functionality
History : 25/03/2021 - v1.0 - Load basic project file.
"""

import datetime
import sqlite3
from functools import wraps

from flask import Flask, g, render_template, redirect, request, session, url_for

__author__ = "Martin Siddons, Chris Sutton, Sam Humphreys, Steven Diep"
__copyright__ = "Copyright 2021, CMP-UG4"
__credits__ = ["Martin Siddons", "Chris Sutton", "Sam Humphreys", "Steven Diep"]
__version__ = "1.0"
__email__ = "gny17hvu@uea.ac.uk"
__status__ = "Development"  # or "Production"


app = Flask(__name__)
app.secret_key = 'thisisabadsecretkey'  # KEK

DATABASE = 'database.sqlite'


# TODO: This is really badly written, will need rewriting and splitting into multiple functions for different
#  accounts. Also needs moving to db.py (issue 15). -MS
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)

    def make_dicts(cursor, row):
        return dict((cursor.description[idx][0], value)
                    for idx, value in enumerate(row))

    db.row_factory = make_dicts
    return db


# TODO: Move this into db.py (issue 15) -MS
# TODO: needs a rewrite or reimplementation for security. (issue 27) -MS
def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


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
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


@app.route("/")
@std_context
def index():
    # TODO: No (issue 27) -MS
    # TODO: Move it to db.py (issue 15) -MS
    posts = query_db('SELECT posts.creator,posts.date,posts.title,posts.content,users.name,users.username FROM posts '
                     'JOIN users ON posts.creator=users.userid ORDER BY date DESC LIMIT 10')

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
    # TODO: Move it to db.py (Issue 15) -MS
    # TODO: Rewrite (Issue 27) -MS
    cid = query_db('SELECT userid FROM users WHERE username="%s"' % uname)
    if len(cid) < 1:
        return 'No such user'

    # TODO: Move it to db.py (Issue 15) -MS
    # TODO: Rewrite (Issue 27) -MS
    cid = cid[0]['userid']
    query = 'SELECT date,title,content FROM posts WHERE creator=%s ORDER BY date DESC' % cid

    context = request.context

    def fix(item):
        item['date'] = datetime.datetime.fromtimestamp(item['date']).strftime('%Y-%m-%d %H:%M')
        return item

    query_db(query)
    context['posts'] = map(fix, query_db(query))
    return render_template('user_posts.html', **context)


# TODO: Move most of this to auth.py (Issue 10) -MS
# TODO: Move the rest to db.py (Issue 15) -MS
# TODO: Rewrite (Issue 27) -MS
@app.route("/login/", methods=['GET', 'POST'])
@std_context
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    context = request.context

    if len(username) < 1 and len(password) < 1:
        return render_template('auth/login.html', **context)

    query = "SELECT userid FROM users WHERE username='%s'" % username
    account = query_db(query)
    user_exists = len(account) > 0

    query = "SELECT userid FROM users WHERE username='%s' AND password='%s'" % (username, password)
    print(query)
    account2 = query_db(query)
    print(account)
    pass_match = len(account2) > 0

    #TODO: Rewrite this to ensure timing and message returned are the same (Issue 12) -MS
    if user_exists:
        if pass_match:
            session['userid'] = account[0]['userid']
            session['username'] = username
            return redirect(url_for('index'))
        else:
            # Return wrong password
            return redirect(url_for('login_fail', error='Wrong password'))
    else:
        # Return no such user
        return redirect(url_for('login_fail', error='No such user'))


# Not sure if this code needs moving out anywhere since I think it's a flask thing. -MS
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


# TODO: Move to db.py (Issue 15) -MS
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

    query = "INSERT INTO posts (creator, date, title, content) VALUES ('%s',%d,'%s','%s')" % (
        userid, date, title, content)
    query_db(query)

    get_db().commit()

    return redirect('/')


# TODO: Move to db.py (Issue 15) -MS
# TODO: Rewrite db stuff (Issue 27) -MS
@app.route("/reset/", methods=['GET', 'POST'])
@std_context
def reset():
    context = request.context

    email = request.form.get('email', '')
    if email == '':
        return render_template('auth/reset_request.html')

    query = "SELECT email FROM users WHERE email='%s'" % email
    exists = query_db(query)
    if len(exists) < 1:
        return render_template('auth/no_email.html', **context)
    else:
        context['email'] = email
        return render_template('auth/sent_reset.html', **context)


# TODO: Move to db.py (Issue 15) -MS
# TODO: Rewrite db stuff (Issue 27) -MS
@app.route("/search/")
@std_context
def search_page():
    context = request.context
    search = request.args.get('s', '')

    query = "SELECT username FROM users WHERE username LIKE '%%%s%%';" % search
    users = query_db(query)
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
