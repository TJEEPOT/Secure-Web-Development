import unittest

import db
from blog import app


class MyTestCase(unittest.TestCase):
    def test_create_account(self):
        with app.app_context():
            client = app.test_client(self)
            data = {'name': 'test account',
                    'email': 'test.account@atestingemail.tk',
                    'username': 'testing',
                    'password': 'test_password1'}

            response = client.post('/create_account/', data=data, follow_redirects=True)
            self.assertIn(b'Check your email for confirmation', response.data)

            # check the account exists
            user_id = db.get_user('testing')['userid']
            self.assertIsNotNone(user_id)

            # ensure that the response for an existing account comes back the same
            response = client.post('/create_account/', data=data, follow_redirects=True)
            self.assertIn(b'Check your email for confirmation', response.data)

            # clean up the db
            query = """ DELETE FROM users WHERE userid=? """
            db.query_db(query, (user_id,))
            db.get_db().commit()


if __name__ == '__main__':
    unittest.main()
