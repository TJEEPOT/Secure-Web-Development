# !/usr/bin/env python
# -*- coding: utf-8 -*-

""" Functions for the database
File    : db.py
Date    : Thursday 25 March 2021
Desc.   : Handles functions for interaction with the database
History : 25/03/2021 - v1.0 - Load basic project file.
"""

__author__ = "Martin Siddons, Chris Sutton, Sam Humphreys, Steven Diep"
__copyright__ = "Copyright 2021, CMP-UG4"
__credits__ = ["Martin Siddons", "Chris Sutton", "Sam Humphreys", "Steven Diep"]
__version__ = "1.0"
__email__ = "gny17hvu@uea.ac.uk"
__status__ = "Development"  # or "Production"

import sqlite3

from flask import g

DATABASE = 'database.sqlite'


# TODO: This is really badly written, will need rewriting and splitting into multiple functions for different
#  accounts. (Issue 24) -MS
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)

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


def update_db(query, args=()):
    cur = get_db().cursor()
    cur.execute(query, args)
    get_db().commit()

def get_salt(username):
    pass


# TODO: This won't be needed when get_salt() is implemented -MS
# TODO: Rewrite (Issue 27) -MS
def get_user(username):
    query = "SELECT userid FROM users WHERE username=?"
    account = query_db(query, (username,))
    return account


# TODO: Rewrite (Issue 27) -MS
def get_password(account, password, username):
    query = "SELECT userid FROM users WHERE username='%s' AND password='%s'" % (username, password)
    print(query)
    account2 = query_db(query)
    print(account)
    pass_match = len(account2) > 0
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
    return query


# TODO: Rewrite db stuff (Issue 27) -MS
def get_email(email):
    query = "SELECT email FROM users WHERE email='%s'" % email
    return query


# TODO: Rewrite db stuff (Issue 27) -MS
def get_users(search):
    query = "SELECT username FROM users WHERE username LIKE '%%%s%%';" % search
    return query


def set_two_factor(userid: str, datetime :str, code: str):
    query = f"INSERT or REPLACE INTO twofactor VALUES (?,?,?,?)"
    update_db(query, (userid, datetime, code, 3))


def del_two_factor(userid: str):
    query = "DELETE FROM twofactor WHERE user=?"
    update_db(query, (userid,))

def tick_down_two_factor_attempts(userid: str):
    current_attempts = query_db("SELECT attempts FROM twofactor WHERE user=?",(userid,))[0]['attempts']
    update_db("UPDATE twofactor SET attempts =? WHERE user =?", (current_attempts-1, userid))
