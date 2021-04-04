# !/usr/bin/env python
# -*- coding: utf-8 -*-

""" Functions for the database
File    : db.py
Date    : Thursday 25 March 2021
Desc.   : Handles functions for interaction with the database
History : 25/03/2021 - v1.0 - Load basic project file.
          02/04/2021 - v1.1 - Create add_user().
          03/04/2021 - v1.2 - Create get_login(), merge in get_salt() and get_password()
"""

__author__ = "Martin Siddons, Chris Sutton, Sam Humphreys, Steven Diep"
__copyright__ = "Copyright 2021, CMP-UG4"
__credits__ = ["Martin Siddons", "Chris Sutton", "Sam Humphreys", "Steven Diep"]
__version__ = "1.2"
__email__ = "gny17hvu@uea.ac.uk"
__status__ = "Development"  # or "Production"

import os
import sqlite3
import time

from flask import g

import auth
import validation

# TODO: Move these into memory before going into production - MS
DATABASE = 'database.sqlite'
PEPPER = 'VEZna2zRIblhQPw-NqY3aQ'


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


# TODO: Rewrite (Issue 27) -MS
def get_user(username):
    query = "SELECT userid FROM users WHERE username='%s'" % username
    account = query_db(query, one=True)
    return account


def get_login(username, password):
    start_time = time.time()
    # Return the user's salt from the db or None if not found
    query = "SELECT salt FROM users WHERE username=?"
    salt = query_db(query, (username,), one=True)
    if salt is None:
        finish_time = time.time()
        processing_time = finish_time - start_time
        time.sleep(1 - processing_time)  # we want this entire function to take one second
        return None

    salt = salt['salt']
    password = auth.ug4_hash(password + salt + PEPPER)

    query = "SELECT userid FROM users WHERE username=? AND password=?"
    user_id = query_db(query, (username, password), one=True)
    if user_id is not None:
        user_id = user_id['userid']

    finish_time = time.time()
    processing_time = finish_time - start_time
    time.sleep(1 - processing_time)  # as above, extend processing time to one second

    return user_id


def add_user(name, email, username, password):
    start_time = time.time()
    # first check if the user exists
    query = "SELECT userid FROM users WHERE email=?"
    email_exists = query_db(query, (email,))
    query = "SELECT userid FROM users WHERE username=?"
    username_exists = query_db(query, (username,))
    if email_exists or username_exists:
        finish_time = time.time()
        processing_time = finish_time - start_time
        time.sleep(1 - processing_time)  # conceal if the user already exists
        return False

    # if it's a new user, build their salt and hash and add them to the db
    salt = auth.generate_salt()
    password = password + salt + PEPPER
    pw_hash = auth.ug4_hash(password)
    query = "INSERT INTO users (username, name, password, email, salt) VALUES (?,?,?,?,?)"
    query_db(query, (username, name, pw_hash, email, salt))
    get_db().commit()

    finish_time = time.time()
    processing_time = finish_time - start_time
    time.sleep(1 - processing_time)  # ensure the processing time remains one second
    return True


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
