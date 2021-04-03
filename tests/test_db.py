import unittest

import db
from blog import app


class MyTestCase(unittest.TestCase):
    def test_get_login_correct(self):
        with app.app_context():
            self.assertEqual(0, db.get_login("aking", "password"))

    def test_get_login_incorrect_user(self):
        with app.app_context():
            self.assertEqual(None, db.get_login("IDoNotExist", "password"))

    def test_get_login_incorrect_password(self):
        with app.app_context():
            self.assertEqual(None, db.get_login("aking", "ThisIsNotThePassword"))


if __name__ == '__main__':
    unittest.main()
