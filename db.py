# !/usr/bin/env python
# -*- coding: utf-8 -*-

""" Functions for the database
File    : db.py
Date    : Thursday 25 March 2021
Desc.   : Handles functions for interaction with the database
History : 25/03/2021 - v1.0 - Load basic project file.
          02/04/2021 - v1.1 - Create add_user().
          03/04/2021 - v1.2 - Create get_login(), merge in get_salt() and get_password()
          06/04/2021 - v1.3 - Added validation to all input fields
          27/04/2021 - v1.4 - Added database encryption/decryption code
"""

__author__ = "Martin Siddons, Chris Sutton, Sam Humphreys, Steven Diep"
__copyright__ = "Copyright 2021, CMP-UG4"
__credits__ = ["Martin Siddons", "Chris Sutton", "Sam Humphreys", "Steven Diep"]
__version__ = "1.4"
__email__ = "gny17hvu@uea.ac.uk"
__status__ = "Development"  # or "Production"


from datetime import datetime
import os
import pathlib
import re  # to validate two factor code now that it has been removed from validation

import sqlite3
import time

from dotenv import load_dotenv
from flask import g

import auth
import blowfish
import validation

load_dotenv(override=True)
SEK = blowfish.decrypt("dQw4w9WgXcQ", 0, os.environ.get("UG_4_SEK"))
DBN = blowfish.decrypt(SEK, 0, os.environ.get("UG_4_DBN"))
print(DBN)
DATABASE = blowfish.decrypt(SEK, DBN, os.environ.get("UG_4_DATABASE"))
PEPPER = blowfish.decrypt(SEK, DBN, os.environ.get("UG_4_PEP"))
DBK = blowfish.decrypt(SEK, DBN, os.environ.get("UG_4_DB"))
DATA_FILENAME = pathlib.Path(__file__).with_name('bad_passwords.txt')



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


""" These functions have been designed to utilise a separate user login for each action, 
which requires an upgrade to a database with a server. """


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


def get_user(username):
    valid_user = validation.validate_username(username)
    query = "SELECT userid FROM users WHERE username=?"
    result = query_db(query, (valid_user,), one=True)
    return result['userid'] if result else None


def get_login(email, password):
    start_time = time.time()
    valid_email = validation.validate_email(email)
    valid_password = validation.validate_password(password)

    # email is encrypted in the DB so encrypt it
    encrypted_email = blowfish.encrypt(DBK, DBN, valid_email)

    # Return the user's salt from the db or None if not found
    query = "SELECT salt FROM users WHERE email=?"
    salt = query_db(query, (encrypted_email,), one=True)
    if salt is None or encrypted_email is None or valid_password is None:
        finish_time = time.time()
        processing_time = finish_time - start_time
        time.sleep(max((1 - processing_time), 0))  # we want this entire function to take at least one second
        return None, None

    salt = salt['salt']
    hashed_password = auth.ug4_hash(valid_password + salt + PEPPER)

    query = "SELECT userid, username FROM users WHERE email=? AND password=?"
    details = query_db(query, (encrypted_email, hashed_password), one=True)

    finish_time = time.time()
    processing_time = finish_time - start_time
    time.sleep(max((1 - processing_time), 0))  # as above, extend processing time to at least one second

    return (details['userid'], details['username']) if details else (None, None)


def add_user(name, email, username, password):
    """ Validates and inserts user details into DB on successful validation.
    :return: error message or None if validation was successful
    :rtype str:
    """
    start_time = time.time()

    # validate the entered form details
    valid_name = validation.validate_text(name, max_length=100)
    valid_email = validation.validate_email(email)
    valid_username = validation.validate_username(username)
    valid_password = validation.validate_password(password)
    usetwofactor = '0'

    if not valid_name:
        return 'Name validation failed.'
    if not valid_email:
        return 'Email validation failed.'
    if not valid_username:
        return 'Username validation failed.'
    if not valid_password:
        return 'Password validation failed.'

    if is_weak_password(valid_password):
        return 'Password entered is vulnerable to attacks'

    # email is encrypted in the DB so encrypt it
    encrypted_email = blowfish.encrypt(DBK, DBN, valid_email)


    # check if the user exists
    query = "SELECT userid FROM users WHERE email=?"
    email_exists = query_db(query, (encrypted_email,))
    query = "SELECT userid FROM users WHERE username=?"
    username_exists = query_db(query, (valid_username,))

    if username_exists:
        return 'Username already exists, please choose another.'  # does not require hiding since this is public info
    if email_exists:
        finish_time = time.time()
        processing_time = finish_time - start_time
        time.sleep(max((1 - processing_time), 0))  # conceal if the user already exists
        return 'Email exists'

    # name is encrypted in the DB so encrypt it
    encrypted_name = blowfish.encrypt(DBK, DBN, valid_name)

    # if it's a new user, build their salt and hash and add them to the db
    salt = auth.generate_salt()
    password = valid_password + salt + PEPPER
    pw_hash = auth.ug4_hash(password)

    query = "INSERT INTO users (username, name, password, email, usetwofactor, salt) VALUES (?,?,?,?,?,?)"
    insert_db(query, (valid_username, encrypted_name, pw_hash, encrypted_email, usetwofactor, salt))

    finish_time = time.time()
    processing_time = finish_time - start_time
    time.sleep(max((1 - processing_time), 0))  # ensure the processing time remains at least one second
    return None


def update_user(userid, username, email, usetwofactor):
    """ Validates and updates user details into DB on successful validation.
     :return: error message or None if validation was successful
     :rtype str:
     """
    start_time = time.time()

    # validate the entered form details
    valid_email = validation.validate_email(email)
    valid_username = validation.validate_username(username)

    if not valid_email:
        return 'Email validation failed.'
    if not valid_username:
        return 'Username validation failed.'

    encrypted_email = blowfish.encrypt(SEK, DBN, valid_email)

    query = "UPDATE users SET username = ?, email = ?, usetwofactor = ? WHERE userid = ?"
    update_db(query, (valid_username, encrypted_email, usetwofactor, userid))

    finish_time = time.time()
    processing_time = finish_time - start_time
    time.sleep(max((1 - processing_time), 0))  # ensure the processing time remains at least one second
    return None


def get_all_posts():
    return query_db('SELECT posts.creator,posts.date,posts.title,posts.content,users.username FROM posts '
                    'JOIN users ON posts.creator=users.userid ORDER BY date DESC LIMIT 10')


def get_posts(cid):
    query = 'SELECT date, title, content FROM posts WHERE creator=? ORDER BY date DESC'
    posts = query_db(query, (cid,))
    return posts


def add_post(content, date, title, userid):
    query = "INSERT INTO posts (creator, date, title, content) VALUES (?, ?, ?, ?)"
    validate_title = validation.validate_text(title, max_length=30)
    validate_content = validation.parse_markup(validation.validate_text(content))
    insert_db(query, (userid, date, validate_title, validate_content))


def get_post(userid, title):
    query = "SELECT * from posts where creator=? AND title=?"
    found = query_db(query, (userid, title), one=True)
    return found


def delete_post(userid, title):
    query = "DELETE FROM posts WHERE creator=? AND title=?"
    del_from_db(query, (userid, title))


def get_users(search):
    query = "SELECT username FROM users WHERE username LIKE ? LIMIT 20"
    validated_search = validation.validate_text(search, max_length=30)
    users = query_db(query, ('%' + validated_search + '%',))
    return users, validated_search


def get_two_factor(uid):
    query = "SELECT * FROM twofactor WHERE user = ?"
    result = query_db(query, (uid,), one=True)

    if result is None:
        return None

    # code is encrypted in the DB so decrypt it
    result['code'] = blowfish.decrypt(DBK, DBN, result['code'])
    return result


def set_two_factor(userid: int, date_time: str, code: str):
    # code is encrypted in the DB so encrypt it
    encrypted_code = blowfish.encrypt(DBK, DBN, code)

    query = f"INSERT or REPLACE INTO twofactor VALUES (?,?,?,?)"
    insert_db(query, (userid, date_time, encrypted_code, 3))


def del_two_factor(userid: int):
    query = "DELETE FROM twofactor WHERE user=?"
    del_from_db(query, (userid,))


def tick_down_two_factor_attempts(userid: int):
    current_attempts = query_db("SELECT attempts FROM twofactor WHERE user=?", (userid,), one=True)['attempts']
    update_db("UPDATE twofactor SET attempts =? WHERE user =?", ((current_attempts - 1), userid))


def get_user_id_from_email(email: str):
    validated_email = validation.validate_email(email)
    if validated_email is None:
        return None

    # email is encrypted in the DB so encrypt it
    encrypted_email = blowfish.encrypt(DBK, DBN, validated_email)

    query = "SELECT userid FROM users WHERE email=?"
    userid = query_db(query, (encrypted_email,), one=True)
    if userid is None:
        return None

    userid = userid['userid']
    return userid


def get_reset_codes(uid):
    query = "SELECT * FROM reset_codes WHERE user = ?"
    result = query_db(query, (uid,), one=True)

    # database item decryption
    result["code"] = blowfish.decrypt(DBK, DBN, result["code"])
    return result


def insert_reset_code(email: str, timestamp: str, code: str):
    email = validation.validate_email(email)
    userid = get_user_id_from_email(email)
    ret = False
    if userid is not None:
        # code is encrypted in the DB so encrypt it
        encrypted_code = blowfish.encrypt(DBK, DBN, code)
        query = f"INSERT or REPLACE INTO reset_codes VALUES (?,?,?)"
        insert_db(query, (userid, timestamp, encrypted_code))
        ret = True
    return ret


def delete_reset_code(email: str):
    query = "DELETE FROM reset_codes WHERE user=?"
    userid = get_user_id_from_email(email)
    del_from_db(query, (userid,))


def validate_reset_code(email: str, code: str):
    valid_email = validation.validate_email(email)
    code = re.match(r"^[\w]{6}$", code)
    valid_code = code.string if code else None
    ret = False
    #   success
    userid = get_user_id_from_email(valid_email)
    if userid is not None and valid_code is not None:
        encrypted_code = blowfish.encrypt(DBK, DBN, valid_code)
        query = "SELECT * FROM reset_codes WHERE user=? AND code=?"
        result = query_db(query, (userid, encrypted_code), one=True)
        ret = result
    return ret


def insert_and_retrieve_reset_token(email: str, timestamp: str):
    valid_email = validation.validate_email(email)
    userid = get_user_id_from_email(valid_email)
    if userid is None:
        return None

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
    valid_email = validation.validate_email(email)
    userid = get_user_id_from_email(valid_email)  # encrypted within

    if userid is not None:
        query = "DELETE FROM reset_tokens WHERE user=?"
        del_from_db(query, (userid,))


def get_reset_token(email: str):
    valid_email = validation.validate_email(email)
    userid = get_user_id_from_email(valid_email)
    token = None
    if userid is not None:
        query = "SELECT token FROM reset_tokens WHERE user=?"
        token = query_db(query, (userid,), one=True)['token']
    return token


def is_weak_password(password: str):
    password = validation.validate_password(password)
    weak = False
    if password:    # needed incase validation fails
        with open(DATA_FILENAME, 'r') as file:
            for line in file:
                line = line.strip("\n")
                if password == line:
                    weak = True
                    break
    return weak
  
  
def update_password_from_email(email: str, password: str):
    valid_email = validation.validate_email(email)
    valid_password = validation.validate_password(password)
    userid = get_user_id_from_email(valid_email)

    ret = False
    if userid is not None and valid_password is not None:
        if is_weak_password(valid_password):
            return ret

        first_query = "SELECT salt FROM users WHERE userid=?"
        salt = query_db(first_query, (userid,), one=True)
        salt = salt['salt']
        valid_password = auth.ug4_hash(valid_password + salt + PEPPER)
        query = "UPDATE users SET password =? WHERE userid =?"
        update_db(query, (valid_password, userid))
        ret = True

    return ret


# if we're out of time, kick them back to the login screen
def within_time_limit(db_time: str, curr_time=datetime.now()):
    db_time_as_dt = datetime.strptime(db_time, '%Y-%m-%d %H:%M:%S')

    difference = curr_time - db_time_as_dt
    total_secs = difference.total_seconds()
    total_mins = total_secs/60
    limit = 5  # Max time for codes to work in minutes
    return total_mins < limit


def user_twofactor_code_within_time_limit(user_id: str):
    two_factor = get_two_factor(user_id)
    original_time = two_factor['timestamp']
    return within_time_limit(original_time)


def user_reset_code_within_time_limit(user_id: str):
    reset_codes = get_reset_codes(user_id)
    original_time = reset_codes['timestamp']
    return within_time_limit(original_time)


def find_two_factor(user_id):
    query = 'SELECT usetwofactor, email FROM users WHERE userid =?'
    results = query_db(query, (user_id,), one=True)

    # email is encrypted in the DB so decrypt it
    results['email'] = blowfish.decrypt(DBK, DBN, results['email'])
    return results


def get_lockout_time(ip_address):
    query = 'SELECT lockouttime FROM loginattempts WHERE ip =?'
    lockout_time = query_db(query, (ip_address,), one=True)
    if lockout_time is None or lockout_time['lockouttime'] is None:
        return None
    return datetime.strptime(lockout_time['lockouttime'], '%Y-%m-%d %H:%M:%S.%f')
