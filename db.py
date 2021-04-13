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
import re  # to validate two factor code now that it has been removed from validation
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


def insert_db(query, args=()):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(query, args)
    conn.commit()


def update_db(query, args=()):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(query, args)
    conn.commit()


def del_from_db(query, args=()):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(query, args)
    conn.commit()


# TODO: Rewrite (Issue 27) -MS
def get_user(username):
    query = "SELECT userid FROM users WHERE username=?"
    account = query_db(query, (username,), one=True)
    return account


def get_login(username, password):
    start_time = time.time()
    # Return the user's salt from the db or None if not found
    query = "SELECT salt FROM users WHERE username=?"
    salt = query_db(query, (username,), one=True)
    if salt is None:
        finish_time = time.time()
        processing_time = finish_time - start_time
        time.sleep(max((1 - processing_time), 0))  # we want this entire function to take at least one second
        return None

    salt = salt['salt']
    password = auth.ug4_hash(password + salt + PEPPER)

    query = "SELECT userid FROM users WHERE username=? AND password=?"
    user_id = query_db(query, (username, password), one=True)
    if user_id is not None:
        user_id = user_id['userid']

    finish_time = time.time()
    processing_time = finish_time - start_time
    time.sleep(max((1 - processing_time), 0))  # as above, extend processing time to at least one second

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
        time.sleep(max((1 - processing_time), 0))  # conceal if the user already exists
        return False

    # if it's a new user, build their salt and hash and add them to the db
    salt = auth.generate_salt()
    password = password + salt + PEPPER
    pw_hash = auth.ug4_hash(password)
    query = "INSERT INTO users (username, name, password, email, salt) VALUES (?,?,?,?,?)"
    insert_db(query, (username, name, pw_hash, email, salt))

    finish_time = time.time()
    processing_time = finish_time - start_time
    time.sleep(max((1 - processing_time), 0))  # ensure the processing time remains at least one second
    return True


def get_all_posts():
    return query_db('SELECT posts.creator,posts.date,posts.title,posts.content,users.name,users.username FROM posts '
                    'JOIN users ON posts.creator=users.userid ORDER BY date DESC LIMIT 10')


# TODO: Rewrite (Issue 27) -MS
def get_posts(cid):
    query = 'SELECT date,title,content FROM posts WHERE creator=? ORDER BY date DESC'
    posts = query_db(query, (cid,))
    return posts


# TODO: Rewrite db stuff (Issue 27) -MS
def add_post(content, date, title, userid):
    query = "INSERT INTO posts (creator, date, title, content) VALUES (?, ?, ?, ?)"
    insert_db(query, (userid, date, title, content))


# TODO: Rewrite db stuff (Issue 27)... wait, why does this even exist? -MS
def get_email(email):
    query = "SELECT email FROM users WHERE email=?"
    email = query_db(query, (email,), one=True)
    return email


# TODO: Rewrite db stuff (Issue 27) and especially for validation -MS
def get_users(search):
    query = "SELECT username FROM users WHERE username LIKE ?"
    users = query_db(query, ('%' + search + '%',))
    return users


def get_two_factor(uid):
    query = "SELECT * FROM twofactor WHERE user = ?"
    result = query_db(query, (uid,), one=True)
    return result


def set_two_factor(userid: str, datetime: str, code: str):
    query = f"INSERT or REPLACE INTO twofactor VALUES (?,?,?,?)"
    insert_db(query, (userid, datetime, code, 3))


def del_two_factor(userid: str):
    query = "DELETE FROM twofactor WHERE user=?"
    del_from_db(query, (userid,))


def tick_down_two_factor_attempts(userid: str):
    current_attempts = query_db("SELECT attempts FROM twofactor WHERE user=?", (userid,), one=True)['attempts']
    update_db("UPDATE twofactor SET attempts =? WHERE user =?", ((current_attempts - 1), userid))


def get_user_id_from_email(email: str):
    query = "SELECT userid FROM users WHERE email=?"
    userid = query_db(query, (email,), one=True)
    if userid:
        userid = userid['userid']
    return userid


def insert_reset_code(email: str, timestamp: str, code: str):
    email = validation.validate_email(email)
    userid = get_user_id_from_email(email)
    ret = False
    if userid is not None:
        query = f"INSERT or REPLACE INTO reset_codes VALUES (?,?,?)"
        insert_db(query, (userid, timestamp, code))
        ret = True
    return ret


def delete_reset_code(email: str):
    query = "DELETE FROM reset_codes WHERE user=?"
    userid = get_user_id_from_email(email)
    del_from_db(query, (userid,))


def validate_reset_code(email: str, code: str):
    email = validation.validate_email(email)
    code = re.match(r"^[\w]{6}$", code)
    code = code.string if code else None
    ret = False
    #   success
    userid = get_user_id_from_email(email)
    if userid is not None and code is not None:
        userid = get_user_id_from_email(email)
        query = "SELECT * FROM reset_codes WHERE user=? AND code=?"
        result = query_db(query, (userid, code), one=True)
        ret = result
    return ret


def insert_and_retrieve_reset_token(email: str, timestamp: str):
    email = validation.validate_email(email)
    userid = get_user_id_from_email(email)
    first_query = "SELECT * FROM reset_codes WHERE user=?"
    result = query_db(first_query, (userid,), one=True)
    reset_time_stamp = result['timestamp']
    code = result['code']
    raw_token_string = email + str(userid) + code + reset_time_stamp
    token = auth.ug4_hash(raw_token_string, 50)  # using Martin's hash function for a quick token
    second_query = f"INSERT or REPLACE INTO reset_tokens VALUES (?,?,?)"
    insert_db(second_query, (userid, timestamp, token))
    return token


def delete_reset_token(email: str):
    email = validation.validate_email(email)
    userid = get_user_id_from_email(email)
    if userid is not None:
        query = "DELETE FROM reset_tokens WHERE user=?"
        del_from_db(query, (userid,))


def get_reset_token(email: str):
    email = validation.validate_email(email)
    userid = get_user_id_from_email(email)
    token = None
    if userid is not None:
        query = "SELECT token FROM reset_tokens WHERE user=?"
        token = query_db(query, (userid,), one=True)['token']
    return token


def update_password_from_email(email: str, password: str):
    email = validation.validate_email(email)
    password = validation.validate_password(password)
    userid = get_user_id_from_email(email)
    ret = False
    if userid is not None and password is not None:
        first_query = "SELECT salt FROM users WHERE userid=?"
        salt = query_db(first_query, (userid,), one=True)
        salt = salt['salt']
        password = auth.ug4_hash(password + salt + PEPPER)
        query = "UPDATE users SET password =? WHERE userid =?"
        update_db(query, (password, userid))
        ret = True

    return ret
