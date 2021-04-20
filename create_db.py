import datetime
import os
import random
import re
import sqlite3
from dotenv import load_dotenv

import auth

# load environment variables from file TODO: Adjust these before going to prod.
load_dotenv(override=True)
DATABASE = os.environ.get("UG_4_DATABASE")
PEPPER = os.environ.get("UG_4_PEP")

# Simple user blog site

# From http://listofrandomnames.com/index.cfm?textarea
USERS = map(lambda x: x.strip(), re.split('[\r\n]+', '''Aleida King  
Billye Quayle  
Mildred Beaty  
Adeline Beyers  
Tricia Wendel  
Kizzy Bedoya  
Marx Warn  
Hulda Culberson  
Devona Morvant  
Winston Tomasello  
Dede Frame  
Lissa Follansbee  
Timmy Dapolito  
Gracie Lonon  
Nana Officer  
Yuri Kruchten  
Chante Brasch  
Edmond Toombs  
Scott Schwan  
Lean Beauregard  
Norberto Petersen  
Carole Costigan  
Chantel Drumheller  
Riva Redfield  
Jennie Sandifer  
Vivian Cimini  
Goldie Hayworth  
Tomeka Kimler  
Micaela Juan  
Jerrold Tjaden  
Collene Olson  
Edna Serna  
Cleveland Miley  
Ena Haecker  
Huey Voelker  
Annamae Basco  
Florentina Quinlan  
Eryn Chae  
Mozella Mcknight  
Ruby Cobble  
Jeannine Simerly  
Colby Tabares  
Jason Castorena  
Henry Ackerman  
Betsy Mendelsohn  
Nicolle Leverette  
Bobette Tuel  
Amy Nonymous  
Danica Halverson  
Consuelo Crown'''))


def create():
    db = sqlite3.connect(DATABASE)

    c = db.cursor()

    c.execute(
        '''CREATE TABLE users (userid integer PRIMARY KEY, username VARCHAR(32), name TEXT, password VARCHAR(64), 
        email TEXT, usetwofactor INTEGER default 0, salt TEXT)''')
    c.execute(
        '''CREATE TABLE posts (creator integer REFERENCES users(userid), date INTEGER, title TEXT, content TEXT)''')
    c.execute('''CREATE INDEX user_username on users (username)''')
    c.execute('''CREATE INDEX user_posts on posts (creator,date)''')

    # Twofactor table
    c.execute('''CREATE TABLE twofactor (user integer UNIQUE REFERENCES  users(userid), timestamp TEXT, code TEXT, 
        attempts INTEGER default 3)''')

    # CS: Login attempts table
    c.execute('''CREATE TABLE loginattempts (ip integer UNIQUE, attempts INTEGER default 0, lockouttime TEXT)''')

    # Reset codes
    c.execute('''CREATE TABLE reset_codes (user integer UNIQUE REFERENCES  users(userid), timestamp TEXT, code TEXT)''')
    # Reset tokens
    c.execute('''CREATE TABLE reset_tokens (user integer UNIQUE REFERENCES users(userid),timestamp TEXT, token TEXT)''')
    db.commit()

    user_id = 0
    password = os.environ.get("UG_4_PW")
    rand_password = 'dfhfsdghjsfgskjs'  # TODO: might want to randomise the word used for the password?
    for user in USERS:
        if user == "Aleida King":
            create_content(db, user_id, user, password, 1)  # Expected password
        elif user == "Billye Quayle":
            create_content(db, user_id, user, password, 0)  # Same here for the non-authenticated test account
        else:
            create_content(db, user_id, user, rand_password)
        user_id += 1
    db.commit()


def create_content(db, user_id, name, password, twofac=0):
    salt = auth.generate_salt()
    password = password + salt + PEPPER
    pw_hash = auth.ug4_hash(password)
    c = db.cursor()
    username = '%s%s' % (name.lower()[0], name.lower()[name.index(' ') + 1:])
    email = '%s.%s@fakeemailservice.abcde' % (name.lower()[0], name.lower()[name.index(' ') + 1:])

    c.execute('INSERT INTO users (userid, username, name, password, email,usetwofactor, salt) VALUES (?,?,?,?,?,?,?)',
              (user_id, username, name, pw_hash, email,twofac, salt))
    date = datetime.datetime.now() - datetime.timedelta(28)

    for i in range(random.randrange(4, 8)):
        content = 'Some random text for item %d' % i
        title = 'Item %d' % i
        date = date + datetime.timedelta(random.randrange(1, 3), minutes=random.randrange(1, 120),
                                         hours=random.randrange(0, 6))

        c.execute('INSERT INTO posts (creator,date,title,content) VALUES (?,?,?,?)', (
            user_id, date.timestamp(), title, content
        ))


def delete_db():
    if os.path.exists(DATABASE):
        os.remove(DATABASE)


if __name__ == '__main__':
    delete_db()
    create()
