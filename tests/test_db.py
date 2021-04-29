import time
import unittest
import db
from datetime import datetime, timedelta
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
            account = db.get_login("a.king@fakeemailservice.abcde", "password_1")
            time_diff = time.time() - start_time

            self.assertEqual((0, 'aking'), account)
            self.assertLess(0.95, time_diff)

            # check the function returns None on incorrect username in around one second
            start_time = time.time()
            account = db.get_login("IDoNotExist", "password_1")
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

    def test_two_factor_within_time(self):
            with app.app_context():
                test_user_id = 0        # aking
                test_time = "2012-04-26 20:06:37"  # ('%Y-%m-%d %H:%M:%S') way out of date
                query = "insert into twofactor (user, timestamp, code, attempts) values (?,?,?,?)"
                db.update_db(query, (test_user_id, test_time, "abcdef", 3))
                email = "a.king@fakeemailservice.abcde"
                self.assertFalse(db.user_twofactor_code_within_time_limit(test_user_id))
                db.del_two_factor(test_user_id)
                within_time = datetime.now() - timedelta(minutes=1)
                dt_format = '%Y-%m-%d %H:%M:%S'
                time_string = within_time.strftime(dt_format)
                and_back_to_dt = datetime.strptime(time_string, dt_format)
                db.update_db(query, (test_user_id, and_back_to_dt, "abcdef", 3))
                self.assertTrue(db.user_twofactor_code_within_time_limit(test_user_id))

    def test_delete_reset_token(self):
        with app.app_context():
            test_time =  "2021-04-29 20:06:37"  #('%Y-%m-%d %H:%M:%S')
            query = "insert into reset_tokens (user, timestamp, token) values (?,?,?)"
            db.update_db(query, (0, test_time, "abcdef"))
            email = "a.king@fakeemailservice.abcde"
            db.delete_reset_token(email)
            query2 = "select * from reset_tokens where user=?"
            found_result = db.query_db(query2, (0,))
            self.assertEqual(found_result, [])


        pass
if __name__ == '__main__':
    unittest.main()
