import time
import unittest

import db
from blog import app

# Integration testing for all components
# more tests should be included for common attacks before this goes live


class MyTestCase(unittest.TestCase):
    def test_create_account(self):
        client = app.test_client(self)
        data = {'name': 'test account',
                'email': 'test.account@atestingemail.tk',
                'username': 'testing',
                'password': 'test_password1'}

        # ensure the account doesn't exist
        with app.app_context():
            user_id = db.get_user('testing')
            if user_id:
                self.delete_user(user_id)

        # create the account - this should take around one second
        start_time = time.time()
        response = client.post('/create_account/', data=data, follow_redirects=True)
        time_diff = time.time() - start_time

        self.assertIn(b'Check your email for confirmation', response.data)
        self.assertLess(0.95, time_diff)
        self.assertGreater(1.45, time_diff)  # needs to be high for batch testing

        # check the account exists
        with app.app_context():
            user_id = db.get_user('testing')
            self.assertIsNotNone(user_id)

        # ensure that the response for an existing account comes back the same and also take a second
        start_time = time.time()
        response = client.post('/create_account/', data=data, follow_redirects=True)
        time_diff = time.time() - start_time

        self.assertIn(b'Check your email for confirmation', response.data)
        self.assertLess(0.95, time_diff)
        self.assertGreater(1.45, time_diff)  # needs to be high for batch testing

        # clean up the db
        self.delete_user(user_id)

    def delete_user(self, user_id):
        with app.app_context():
            query = """ DELETE FROM users WHERE userid=? """
            user_id = user_id['userid']
            db.query_db(query, (user_id,))
            db.get_db().commit()

    def test_index(self):
        response = app.test_client(self).get('/')
        # check search box exists
        self.assertIn(b'<form action="/search/"', response.data)
        # check login box exists
        self.assertIn(b'<div id="loginbox">', response.data)
        self.assertIn(b'a href="/login/">Login</a>', response.data)
        # check posts were retrieved from the database
        self.assertIn(b'<h2>Item', response.data)

    def test_users_posts(self):
        response = app.test_client(self).get('/aking/')
        self.assertIn(b'<h2>Item 0</h2>', response.data)  # check a post exists

        # test if an unknown user returns the correct error message
        response = app.test_client(self).get('/notaking/')
        self.assertEqual(b'User page not found.', response.data)

    def test_login_and_logout(self):
        with app.test_client() as client:
            # test that no data given returns the login page
            response = client.get('/login/')
            self.assertIn(b'<input name="username" id="username" maxlength="32" />', response.data)
            self.assertNotIn(b'Check your email for confirmation', response.data)

            # test that a correct username and password work - should return a result in around one second
            start_time = time.time()
            data = {'username': 'bquayle',
                    'password': 'password'}
            response = client.post('/login/', data=data, follow_redirects=True)
            time_diff = time.time() - start_time

            self.assertIn(b'<strong>User:</strong> bquayle<br />', response.data)
            self.assertLess(0.95, time_diff)
            self.assertGreater(1.45, time_diff)  # needs to be high for batch testing

            # test that the account logs out
            response = client.get('/logout/', follow_redirects=True)
            self.assertNotIn(b'<strong>User:</strong> bquayle<br />', response.data)
            self.assertIn(b'<a href="/login/">Login</a>', response.data)

            # test that an incorrect username does not work - should take around one second
            start_time = time.time()
            data = {'username': 'notbquayle',
                    'password': 'password'}
            response = client.post('/login/', data=data, follow_redirects=True)
            time_diff = time.time() - start_time

            self.assertNotIn(b'<strong>User:</strong> bquayle<br />', response.data)
            self.assertLess(0.95, time_diff)
            self.assertGreater(1.45, time_diff)  # needs to be high for batch testing

            # test that an incorrect password does not work - should take around one second
            start_time = time.time()
            data = {'username': 'bquayle',
                    'password': 'AnIncorrectPassword'}
            response = client.post('/login/', data=data, follow_redirects=True)
            time_diff = time.time() - start_time

            self.assertNotIn(b'<strong>User:</strong> bquayle<br />', response.data)
            self.assertLess(0.95, time_diff)
            self.assertGreater(1.45, time_diff)  # needs to be high for batch testing

    def test_new_post(self):
        with app.test_client() as client:
            # without an active session, we should get a redirect page
            response = client.get('/post/')
            self.assertIn(b'<h1>Redirecting...</h1>', response.data)

            # log in a user and ensure the test post doesn't exist yet
            data = {'username': 'bquayle',
                    'password': 'password'}
            response = client.post('/login/', data=data, follow_redirects=True)

            self.assertNotIn(b'<h2>test title</h2>', response.data)
            self.assertNotIn(b'test content...', response.data)

            # get the blog post page
            response = client.get('/post/')
            self.assertIn(b'<h1>New Post</h1>', response.data)  # ensure the post page is returned

            # make a test post and check it's on the returned index page
            data = {'title': 'test title',
                    'content': 'test content'}
            response = client.post('/post/', data=data, follow_redirects=True)

            self.assertIn(b'<h2>Item', response.data)
            self.assertIn(b'<h2>test title</h2>', response.data)
            self.assertIn(b'test content...', response.data)

            # clean up the db
            with app.app_context():
                query = """ DELETE FROM posts WHERE title=? """
                db.query_db(query, ('test title',))
                db.get_db().commit()

    def test_reset_password(self):
        with app.test_client() as client:
            # without giving an email address, we should get the reset request page
            response = client.get('/reset/')
            self.assertIn(b'<h1>Login</h1>', response.data)
            self.assertNotIn(b'<label for="password">Password:</label>', response.data)

            # check that submitting a correct address will send a reset email
            data = {'email': 'a.king-email.com'}
            response = client.post('/reset/', data=data, follow_redirects=True)
            self.assertIn(b'<p>Sent a reset link to a.king-email.com.</p>', response.data)

            # TODO: submitting an email address not registered to an account should show the same result page as a
            #  registered email, the email sent should then invite them to sign up with an account.
            # data = {'email': 'this.is.not.a.registered.email@someemail.uk'}
            # response = client.post('/reset/', data=data, follow_redirects=True)
            # self.assertIn(b'<p>Sent an email to this.is.not.a.registered.email@someemail.uk.</p>', response.data)

            # TODO: simulate clicking on the reset email link and invite email link to ensure they work correctly

    def test_search(self):
        with app.app_context():
            client = app.test_client()

            # empty search returns all accounts TODO: (should this be changed?)
            response = client.get('/search/', follow_redirects=True)
            self.assertIn(b'<h1>Search results</h1>', response.data)
            self.assertIn(b'<p>aking</p>', response.data)
            self.assertIn(b'<p>wtomasello</p>', response.data)

            # a search for aking returns just that account
            query = {'s': 'aking'}
            response = client.get('/search/', query_string=query, follow_redirects=True)
            self.assertIn(b'<p>Results for: aking</p>', response.data)
            self.assertIn(b'<p>aking</p>', response.data)
            self.assertNotIn(b'<p>abasco</p>', response.data)

            # a search for 'ki' will return all accounts that have 'ki' in their name
            query = {'s': 'ki'}
            response = client.get('/search/', query_string=query, follow_redirects=True)
            self.assertIn(b'<p>Results for: ki</p>', response.data)
            self.assertIn(b'<p>aking</p>', response.data)
            self.assertIn(b'<p>tkimler</p>', response.data)


if __name__ == '__main__':
    unittest.main()
