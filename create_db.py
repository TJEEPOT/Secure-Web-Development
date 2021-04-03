import datetime
import os
import random
import re
import sqlite3

import auth

# TODO: Move these into memory before going into production - MS
DATABASE = 'database.sqlite'
PEPPER = 'VEZna2zRIblhQPw-NqY3aQ'

# Simple user blog site

# REMOVE THIS SCRIPT ONCE WE'RE WORKING?

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
Asia Mosteller  
Betsy Mendelsohn  
Nicolle Leverette  
Bobette Tuel  
Lizabeth Borchert  
Danica Halverson  
Consuelo Crown'''))


def create():
    db = sqlite3.connect(DATABASE)

    c = db.cursor()

    c.execute(
        '''CREATE TABLE users (userid integer PRIMARY KEY, username VARCHAR(32), name TEXT, password VARCHAR(64), 
        email TEXT, salt TEXT)''')
    c.execute(
        '''CREATE TABLE posts (creator integer REFERENCES users(userid), date INTEGER, title TEXT, content TEXT)''')
    c.execute('''CREATE INDEX user_username on users (username)''')
    c.execute('''CREATE INDEX user_posts on posts (creator,date)''')
    db.commit()

    user_id = 0
    for user in USERS:
        create_content(db, user_id, user)
        user_id += 1
    db.commit()


def create_content(db, user_id, name):
    salt = auth.generate_salt()
    password = 'password' + salt + PEPPER  # TODO: might want to randomise the word used for the password?
    pw_hash = auth.ug4_hash(password)
    c = db.cursor()
    username = '%s%s' % (name.lower()[0], name.lower()[name.index(' ') + 1:])
    email = '%s.%s@email.com' % (name.lower()[0], name.lower()[name.index(' ') + 1:])

    c.execute('INSERT INTO users (userid, username, name, password, email, salt) VALUES (?,?,?,?,?,?)',
              (user_id, username, name, pw_hash, email, salt))
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
