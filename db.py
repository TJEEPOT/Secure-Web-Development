# !/usr/bin/env python
# -*- coding: utf-8 -*-

""" Functions for the database
File    : db.py
Date    : Thursday 25 March 2021
Desc.   : Handles functions for interaction with the database
History : 25/03/2021 - v1.0 - Load basic project file.
          03/04/2021 - v1.1 - create add_user().
"""

__author__ = "Martin Siddons, Chris Sutton, Sam Humphreys, Steven Diep"
__copyright__ = "Copyright 2021, CMP-UG4"
__credits__ = ["Martin Siddons", "Chris Sutton", "Sam Humphreys", "Steven Diep"]
__version__ = "1.1"
__email__ = "gny17hvu@uea.ac.uk"
__status__ = "Development"  # or "Production"

import os
import sqlite3
import time

from flask import g

DATABASE = 'database.sqlite'


# TODO: This is really badly written, will need rewriting and splitting into multiple functions for different
#  accounts. (Issue 24) -MS
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        db_path = os.path.join(base_dir, DATABASE)
        db = g._database = sqlite3.connect(db_path)

    def make_dicts(cursor, row):
        return dict((cursor.description[idx][0], value)
                    for idx, value in enumerate(row))

    db.row_factory = make_dicts
    return db


# TODO: probably needs a rewrite or reimplementation for security. (issue 27) -MS
def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


def get_salt(username):
    pass


# TODO: Rewrite (Issue 27) -MS
def get_user(username):
    query = "SELECT userid FROM users WHERE username='%s'" % username
    account = query_db(query, one=True)
    return account


def add_user(name, email, username, password, salt):
    # first check if the user exists
    query = "SELECT userid FROM users WHERE email=?"
    email_exists = query_db(query, (email,))
    query = "SELECT userid FROM users WHERE username=?"
    username_exists = query_db(query, (username,))
    if email_exists or username_exists:
        time.sleep(0.04)  # Conceals if the new user was inserted
        return False

    # if it's a new user, add them to the db
    query = "INSERT INTO users (username, name, password, email, salt) VALUES (?,?,?,?,?)"
    query_db(query, (username, name, password, email, salt))
    get_db().commit()
    return True


# TODO: Rewrite (Issue 27) -MS
def get_password(password, username):
    query = "SELECT userid FROM users WHERE username='%s' AND password='%s'" % (username, password)
    print(query)
    account = query_db(query)
    pass_match = len(account) > 0
    return pass_match


# TODO: No (issue 27) -MS
def get_all_posts():
    return query_db('SELECT posts.creator,posts.date,posts.title,posts.content,users.name,users.username FROM posts '
                    'JOIN users ON posts.creator=users.userid ORDER BY date DESC LIMIT 10')


# TODO: Rewrite (Issue 27) -MS
def get_posts(cid):
    query = 'SELECT date,title,content FROM posts WHERE creator=%s ORDER BY date DESC' % cid
    return query


# TODO: Rewrite db stuff (Issue 27) -MS
def add_post(content, date, title, userid):
    query = "INSERT INTO posts (creator, date, title, content) VALUES ('%s',%d,'%s','%s')" % (
        userid, date, title, content)
    query_db(query)
    get_db().commit()


# TODO: Rewrite db stuff (Issue 27) -MS
def get_email(email):
    query = "SELECT email FROM users WHERE email='%s'" % email
    return query


# TODO: Rewrite db stuff (Issue 27) -MS
def get_users(search):
    query = "SELECT username FROM users WHERE username LIKE '%%%s%%';" % search
    return query