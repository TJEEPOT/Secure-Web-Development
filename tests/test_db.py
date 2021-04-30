import os
import time
import unittest

from dotenv import load_dotenv
from datetime import datetime, timedelta

import blowfish
import db
from blog import app

load_dotenv(override=True)
SEK = blowfish.decrypt("dQw4w9WgXcQ", 0, os.environ.get("UG_4_SEK"))
DBN = blowfish.decrypt(SEK, 0, os.environ.get("UG_4_DBN"))

def delete_user(user_id):
    with app.app_context():
        query = """ DELETE FROM users WHERE userid=? """
        db.del_from_db(query, (user_id,))


class MyTestCase(unittest.TestCase):
    def test_get_db(self):
        with app.app_context():
            self.assertIsNotNone(db.get_db())

    def test_query_db(self):
        with app.app_context():
            # check something is retrieved
            self.assertIsNotNone(db.query_db("SELECT username FROM users WHERE userid = 0"))

            # check args works correctly
            query = "SELECT username FROM users WHERE userid=?"
            self.assertIsNotNone(db.query_db(query, (0,)))

            # check the correct thing is retrieved
            query = "SELECT username FROM users WHERE userid = 0"
            self.assertEqual('aking', db.query_db(query)[0]['username'])

            # check it works for one=True also
            query = "SELECT username FROM users WHERE userid = 0"
            self.assertEqual('aking', db.query_db(query, one=True)['username'])

    def test_get_login(self):
        with app.app_context():
            # check the account is returned in around one second
            start_time = time.time()
            account = db.get_login("a.king@fakeemailservice.abcde", "apassword_1")
            time_diff = time.time() - start_time

            self.assertEqual((0, 'aking'), account)
            self.assertLess(0.95, time_diff)

            # check the function returns None on incorrect username in around one second
            start_time = time.time()
            account = db.get_login("IDoNotExist", "apassword_1")
            time_diff = time.time() - start_time

            self.assertIsNone(account[0])
            self.assertLess(0.95, time_diff)
            self.assertGreater(1.45, time_diff)  # needs to be high for batch testing

            # check the function returns None on incorrect password in around one second
            start_time = time.time()
            account = db.get_login("a.king@fakeemailservice.abcde", "ThisIsNotThePassword")
            time_diff = time.time() - start_time

            self.assertIsNone(account[0])
            self.assertLess(0.95, time_diff)

    def test_get_all_posts(self):
        with app.app_context():
            # check something is retrieved
            self.assertIsNotNone(db.get_all_posts())

    def test_get_user(self):
        with app.app_context():
            user = db.get_user("aking")
            self.assertEqual(0, user)

    def test_get_user_none(self):
        with app.app_context():
            user = db.get_user("user_that_does_not_exist")
            self.assertIsNone(user)

    def test_add_user(self):
        with app.app_context():
            error = db.add_user("name", "name@email.sjse", "username", "password5643")
            self.assertIsNone(error)

            # clear up
            user = db.get_user("username")
            delete_user(user)

    def test_add_user_exists(self):
        with app.app_context():
            error = db.add_user("name", "name@email.sjse", "aking", "password5643")
            self.assertEqual("Username already exists, please choose another.", error)

    def test_add_user_email_exists(self):
        with app.app_context():
            error = db.add_user("asdf ghjkl", "a.king@fakeemailservice.abcde", "sdfff", "password5643")
            self.assertEqual("Email exists", error)

    def test_update_user(self):
        with app.app_context():
            error = db.update_user(0, "aking", "a.king@fakeemailservice.abcde", 0)
            self.assertIsNone(error)
            db.update_user(0, "aking", "a.king@fakeemailservice.abcde", 1)

    def test_add_get_delete_post(self):
        with app.app_context():
            date = datetime.now().timestamp()
            db.add_post("content", date, "title", 0)

            post = db.get_post(0, "title")
            self.assertIsNotNone(post)

            db.delete_post(0, "title")

    def test_get_users(self):
        with app.app_context():
            users, search = db.get_users("")
            self.assertIsNotNone(users)
            self.assertIsNotNone(search)

    def test_set_get_delete_twofactor(self):
        with app.app_context():
            date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            db.set_two_factor(0, date, "abcde")
            result = db.get_two_factor(0)
            self.assertEqual("abcde", result["code"])

            db.del_two_factor(0)

    def test_get_two_factor_none(self):
        with app.app_context():
            code = db.get_two_factor(0)
            self.assertIsNone(code)

    def test_two_factor_within_time(self):
        with app.app_context():
            test_user_id = "0"  # aking
            test_time = "2012-04-26 20:06:37"  # ('%Y-%m-%d %H:%M:%S') way out of date
            query = "INSERT INTO twofactor (user, timestamp, code, attempts) VALUES (?,?,?,?)"
            db.update_db(query, (test_user_id, test_time, "abcdef", 3))
            self.assertFalse(db.user_twofactor_code_within_time_limit(test_user_id))

            db.del_two_factor(test_user_id)
            within_time = datetime.now() - timedelta(minutes=1)
            dt_format = '%Y-%m-%d %H:%M:%S'
            time_string = within_time.strftime(dt_format)
            and_back_to_dt = datetime.strptime(time_string, dt_format)
            db.update_db(query, (test_user_id, and_back_to_dt, "abcdef", 3))
            self.assertTrue(db.user_twofactor_code_within_time_limit(test_user_id))
            db.del_two_factor(test_user_id)

    def test_delete_reset_token(self):
        with app.app_context():
            test_time = "2021-04-29 20:06:37"  # ('%Y-%m-%d %H:%M:%S')
            query = "INSERT INTO reset_tokens (user, timestamp, token) VALUES (?,?,?)"
            db.update_db(query, (0, test_time, "abcdef"))
            email = "a.king@fakeemailservice.abcde"
            db.delete_reset_token(email)
            query2 = "SELECT * FROM reset_tokens WHERE user=?"
            found_result = db.query_db(query2, (0,))
            self.assertEqual([], found_result)


if __name__ == '__main__':
    unittest.main()
