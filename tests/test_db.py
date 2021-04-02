from datetime import datetime
import pytest
import db
from blog import app
from db import *

# CS: Makes sure the tests run in the app environment
@pytest.fixture
def app_context():
    with app.app_context():
        yield


# TODO: CS: Probably going to need to be rewritten if database is changed.
def test_get_db(app_context):
    assert get_db() is not None


def test_query_db(app_context):
    # check something is retrieved
    assert db.query_db("SELECT username FROM users WHERE userid = 0", one=False) is not None
    # check the correct thing is retrieved
    assert db.query_db("SELECT username FROM users WHERE userid = 0", one=False)[0]["username"] == "aking"
    # check it works for one=True also
    assert db.query_db("SELECT username FROM users WHERE userid = 0", one=True)["username"] == "aking"
    # check it returns and empty list when query is malformed
    assert db.query_db("jdklwe;jdfklw;", one=False) is None

def test_get_salt(app_context):
    # check it returns the correct salt for user "aking"
    assert db.get_salt("aking") is not None
    # check it doesn't return anything for an incorrect username
    assert db.get_salt("thisisafakeuser") is None

# TODO: CS: Will need to be rewritten when the function is rewritten.
def test_get_password(app_context):
    # check the correct password is retrieved for user "aking"
    assert db.get_password(None, "password", "aking") == True

def test_get_all_posts(app_context):
    # check something is retrieved
    assert db.get_all_posts() is not None

def test_get_posts(app_context):
    # check something is retrieved
    assert db.get_posts(0) is not None
    # check that the correct posts are retrieved with creator "aking"
    assert db.get_posts(0)[1] == "aking"

# TODO: CS: The rest of these are going to need to be written after db.py is complete.

#def test_add_post(app_context):

#def test_get_email(app_context):

#def test_get_users(app_context):


if __name__ == '__main__':
    pytest.main()
