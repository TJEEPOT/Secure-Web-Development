import time
import unittest
import db
from blog import app


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

    # get_posts can not be tested.

    # def test_add_post(app_context):

    # def test_get_email(app_context):

    # def test_get_users(app_context):


if __name__ == '__main__':
    unittest.main()
