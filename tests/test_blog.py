from datetime import datetime, timedelta
import time
import unittest

import db
from blog import app

# Integration testing for all components, includes common attacks


def delete_user(user_id):
    with app.app_context():
        query = """ DELETE FROM users WHERE userid=? """
        db.del_from_db(query, (user_id,))


class MyTestCase(unittest.TestCase):
    def test_create_account_success(self):
        client = app.test_client(self)

        # get the account creation page
        response = client.get('/create_account/', follow_redirects=True)
        self.assertIn(b'<h1>Create New Account</h1>', response.data)

        # ensure the account doesn't exist
        with app.app_context():
            user_id = db.get_user('testing')
            if user_id:
                delete_user(user_id)

        # create the account - this should take around one second
        data = {'name': 'test account',
                'email': 'test.account@atestingemail.tk',
                'username': 'testing',
                'password': 'test_password1'}
        start_time = time.time()
        response = client.post('/create_account/', data=data, follow_redirects=True)
        time_diff = time.time() - start_time

        self.assertIn(b'Check your email for confirmation', response.data)
        self.assertLess(0.95, time_diff)

        # check the account exists
        with app.app_context():
            user_id = db.get_user('testing')
            self.assertIsNotNone(user_id)

        # ensure that the response for an existing email comes back the same and also take a second
        data.update({'username': 'testingtwo'})
        start_time = time.time()
        response = client.post('/create_account/', data=data, follow_redirects=True)
        time_diff = time.time() - start_time

        self.assertIn(b'Check your email for confirmation', response.data)
        self.assertLess(0.95, time_diff)
        test_overhead = 1
        self.assertGreater(1.05 + test_overhead, time_diff)  # needs to be high for batch testing

        # clean up the db
        delete_user(user_id)

    def test_create_account_failure(self):
        client = app.test_client(self)
        data = {'name': 'test account',
                'email': 'test.account@atestingemail.tk',
                'username': 'testing',
                'password': 'test_password1'}

        # ensure the account doesn't exist
        with app.app_context():
            user_id = db.get_user('testing')
            if user_id:
                delete_user(user_id)

        # test name sqli
        data.update({'name': '\' or 1=1;--'})
        client.post('/create_account/', data=data, follow_redirects=True)
        with app.app_context():
            user_id = db.get_user('testing')
            self.assertIsNotNone(user_id)
            delete_user(user_id)

        # test name XSS
        data.update({'name': '<script>alert(1);</script>'})
        client.post('/create_account/', data=data, follow_redirects=True)
        with app.app_context():
            user_id = db.get_user('testing')
            self.assertIsNotNone(user_id)
            delete_user(user_id)
        data.update({'name': 'test account'})

        # test email sqli
        data.update({'email': '\' or 1=1;--'})
        response = client.post('/create_account/', data=data, follow_redirects=True)
        self.assertIn(b'Email validation failed.', response.data)

        # test email XSS
        data.update({'email': '<script>alert(1);</script>'})
        response = client.post('/create_account/', data=data, follow_redirects=True)
        self.assertIn(b'Email validation failed.', response.data)
        data.update({'email': 'test.account@atestingemail.tk'})

        # test username sqli
        data.update({'username': '\' or 1=1;--'})
        response = client.post('/create_account/', data=data, follow_redirects=True)
        self.assertIn(b'Username validation failed.', response.data)

        # test username XSS
        data.update({'username': '<script>alert(1);</script>'})
        response = client.post('/create_account/', data=data, follow_redirects=True)
        self.assertIn(b'Username validation failed.', response.data)
        data.update({'username': 'testing'})

        # passwords don't need testing since they are hashed before storage, as long as login allows them.

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
            self.assertIn(b'<input name="email" id="email" maxlength="64" />', response.data)
            self.assertNotIn(b'Check your email for confirmation', response.data)

            # test that a correct username and password work - should return a result in around one second
            start_time = time.time()
            data = {'email': 'b.quayle@fakeemailservice.abcde',
                    'password': 'password_1'}
            response = client.post('/login/', data=data, follow_redirects=True)
            time_diff = time.time() - start_time

            self.assertIn(b'<strong>User:</strong> bquayle<br />', response.data)
            self.assertLess(0.95, time_diff)

            # test that the account logs out
            response = client.get('/logout/', follow_redirects=True)
            self.assertNotIn(b'<strong>User:</strong> bquayle<br />', response.data)
            self.assertIn(b'<a href="/login/">Login</a>', response.data)

    def test_incorrect_login(self):
        with app.test_client() as client:
            ip = '127.0.0.1'
            local = {'REMOTE_ADDR': ip}

            # ensure loginattempts is empty
            with app.app_context():
                db.del_from_db("DELETE FROM loginattempts WHERE ip=?", (ip, ))

            # test that an incorrect username does not work - should take around one second
            start_time = time.time()
            data = {'email': 'not.b.quayle@fakeemailservice.abcde',
                    'password': 'password_1'}
            response = client.post('/login/', data=data, follow_redirects=True, environ_base=local)
            time_diff = time.time() - start_time

            self.assertNotIn(b'<strong>User:</strong> bquayle<br />', response.data)
            self.assertIn(b'Incorrect Login Details, 4 attempts remaining', response.data)
            self.assertLess(0.95, time_diff)
            self.assertGreater(1.45, time_diff)  # needs to be high for batch testing

            # test that an incorrect password does not work - should take around one second
            start_time = time.time()
            data = {'email': 'b.quayle@fakeemailservice.abcde',
                    'password': 'AnIncorrectPassword'}
            response = client.post('/login/', data=data, follow_redirects=True, environ_base=local)
            time_diff = time.time() - start_time

            self.assertNotIn(b'<strong>User:</strong> bquayle<br />', response.data)
            self.assertIn(b'Incorrect Login Details, 3 attempts remaining', response.data)
            self.assertLess(0.95, time_diff)

            # use up the remaining attempts
            response = client.post('/login/', data=data, follow_redirects=True, environ_base=local)
            self.assertIn(b'Incorrect Login Details, 2 attempts remaining', response.data)

            response = client.post('/login/', data=data, follow_redirects=True, environ_base=local)
            self.assertIn(b'Incorrect Login Details, 1 attempts remaining', response.data)

            response = client.post('/login/', data=data, follow_redirects=True, environ_base=local)
            self.assertIn(b'Too many login attempts. Login disabled for 15 minutes.', response.data)

            # change stored time to simulate >15 minutes passing
            with app.app_context():
                twenty_minutes_ago = datetime.now() - timedelta(minutes=20)
                db.update_db("UPDATE loginattempts SET lockouttime=? WHERE ip=?", (twenty_minutes_ago, ip))

            #  attempts should now reset
            response = client.post('/login/', data=data, follow_redirects=True, environ_base=local)
            self.assertIn(b'Incorrect Login Details, 4 attempts remaining', response.data)

            # test email sqli
            data.update({'email': '\' or 1=1;--'})
            response = client.post('/login/', data=data, follow_redirects=True)
            self.assertIn(b'Incorrect Login Details', response.data)

            # test email XSS
            data.update({'email': '<script>alert(1);</script>'})
            response = client.post('/login/', data=data, follow_redirects=True)
            self.assertIn(b'Incorrect Login Details', response.data)

            # clear loginattempts
            with app.app_context():
                db.del_from_db("DELETE FROM loginattempts WHERE ip=?", (ip, ))

    def test_new_post(self):
        with app.test_client() as client:
            # without an active session, we should be redirected to the login page
            response = client.get('/post/', follow_redirects=True)
            self.assertIn(b'<input name="email" id="email" maxlength="64" />', response.data)

            # log in a user and ensure the test post doesn't exist yet
            data = {'email': 'b.quayle@fakeemailservice.abcde',
                    'password': 'password_1'}
            response = client.post('/login/', data=data, follow_redirects=True)

            self.assertNotIn(b'<h2>test title</h2>', response.data)
            self.assertNotIn(b'test content...', response.data)

            # get the blog post page
            response = client.get('/post/', follow_redirects=True)
            self.assertIn(b'<h1>New Post</h1>', response.data)  # ensure the post page is returned

            # make a test post and check it's on the returned index page
            data = {'title': 'test title',
                    'content': 'test content'}
            response = client.post('/post/', data=data, follow_redirects=True)

            self.assertIn(b'<h2>Item', response.data)
            self.assertIn(b'<h2>test title</h2>', response.data)
            self.assertIn(b'test content...', response.data)

            # test that an sqli will be disarmed before being stored in the database
            data = {'title': '\' or 1=1 --',
                    'content': '\' or 1=1 --'}
            response = client.post('/post/', data=data, follow_redirects=True)
            self.assertIn(b'<h2>&#39; or 1&#61;1 &#45;&#45;</h2>', response.data)  # title
            self.assertIn(b'<p>\n                &#39; or 1&#61;1 &#45;&#45;...\n                </p>', response.data)

            # test that a post containing malicious JS code will be disarmed (prevents Persistent XSS)
            data = {'title': '<script>alert(1)</script>',
                    'content': '<script>alert(1)</script>'}
            response = client.post('/post/', data=data, follow_redirects=True)
            self.assertIn(b'<h2>&#60;script&#62;alert(1)&#60;&#47;script&#62;</h2>', response.data)
            self.assertIn(b'<p>\n                &#60;script&#62;alert(1)&#60;&#47;script&#62;...', response.data)

            # clean up the db
            with app.app_context():
                query = """ DELETE FROM posts WHERE title=? """
                db.del_from_db(query, ('test title',))
                db.del_from_db(query, ('&#39; or 1&#61;1 &#45;&#45;',))
                db.del_from_db(query, ('&#60;script&#62;alert(1)&#60;&#47;script&#62;',))

    def test_reset_password(self):
        with app.test_client() as client:
            # without giving an email address, we should get the reset request page
            response = client.get('/reset/')
            self.assertIn(b'<h1>Email Reset Request</h1>', response.data)
            self.assertNotIn(b'<label for="password">Password:</label>', response.data)

            # check that submitting a correct address will send a reset email
            data = {'email': 'a.king@fakeemailservice.abcde'}
            response = client.post('/reset/', data=data, follow_redirects=True)
            self.assertIn(b'If this address exists in our system we will send a reset request to you.', response.data)

            data = {'email': 'this.is.not.a.registered.email@someemail.uk'}
            response = client.post('/reset/', data=data, follow_redirects=True)
            self.assertIn(b'If this address exists in our system we will send a reset', response.data)

    def test_reset_request(self):
        data = {'email': 'b.quayle@fakeemailservice.abcde'}
        with app.test_client() as client:
            response = client.post('/reset/', data=data, follow_redirects=True)
            #   get code from db
            reset_codes = db.get_reset_codes(db.get_user_id_from_email(data['email']))
            code = reset_codes['code']
            # valid code and email
            data['code'] = code
            response = client.post('/enter_reset/', data=data, follow_redirects=True)
            self.assertIn(b'New password',response.data)
            #invalid code
            response = client.post('/reset/', data=data, follow_redirects=True)
            data.pop('code')
            data['code'] = "abadwejkdwokeoidjhaodijawiuadhuiadnediuashbd8yeadnijnmeoiauwhidsewdasoidjheo"
            response = client.post('/enter_reset/', data=data, follow_redirects=True)
            self.assertIn(b'Enter Reset Code', response.data)
            # expired code
            data.pop('code')
            response = client.post('/reset/', data=data, follow_redirects=True)
            reset_codes = db.get_reset_codes(db.get_user_id_from_email(data['email']))
            timestamp = reset_codes['timestamp']
            dt_time = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
            dt_time = dt_time.replace(minute=(dt_time.minute-5))
            db.update_db("UPDATE reset_codes SET timestamp =? WHERE user =?",
                          (dt_time, db.get_user_id_from_email(data['email']) ))
            reset_codes = db.get_reset_codes(db.get_user_id_from_email(data['email']))
            data['code'] = reset_codes['code']
            response = client.post('/enter_reset/', data=data, follow_redirects=True)
            self.assertIn(b'That code has expired please start a new reset request!', response.data)
            # full link
            data.pop('code')
            response = client.post('/reset/', data=data, follow_redirects=True)
            reset_codes = db.get_reset_codes(db.get_user_id_from_email(data['email']))
            data['code'] = reset_codes['code']
            response = client.post(f"/enter_reset/?email={data['email']}&code={data['code']}", follow_redirects=True)
            self.assertIn(b'New password', response.data)


    def test_new_password(self):
        data = {'email': 'b.quayle@fakeemailservice.abcde'}
        with app.test_client() as client:
            def get_to_reset():
                response = client.post('/reset/', data=data, follow_redirects=True)
                reset_codes = db.get_reset_codes(db.get_user_id_from_email(data['email']))
                data['code'] = reset_codes['code']
                response = client.post(f"/enter_reset/?email={data['email']}&code={data['code']}", follow_redirects=True)
                data.pop('code')
            get_to_reset()
            token = db.get_reset_token(data['email'])
            data['token'] = token
            data['password'] = 'password_1'
            response = client.post('/reset_password/', data=data, follow_redirects=True)
            self.assertIn(b'Your password has been changed! Please login again.', response.data)
            # invalid token
            data['token'] = "asduwdheiudasdenjjkasdnhiyuenasdnme"
            response = client.post('/reset_password/', data=data, follow_redirects=True)
            self.assertIn(b'Something went wrong with your password reset. Please try again!', response.data)
            # invalid email
            get_to_reset()
            data['email'] = 'b.quayle@failme.please'
            data['token'] = db.get_reset_token('b.quayle@fakeemailservice.abcde')
            response = client.post(f'/reset_password/', data=data, follow_redirects=True)
            self.assertIn(b'Something went wrong with your password reset. Please try again!', response.data)
            data['email'] = 'b.quayle@fakeemailservice.abcde'
            get_to_reset()
            response = client.post(f'/reset_password/', follow_redirects=True)
            self.assertIn(b'Enter A New Password', response.data)


    def test_search(self):
        with app.app_context():
            client = app.test_client()

            # empty search returns all accounts
            response = client.get('/search/', follow_redirects=True)
            self.assertIn(b'<h1>Search results</h1>', response.data)
            self.assertIn(b'<p><a href="/aking">aking</a></p>', response.data)
            self.assertIn(b'<p><a href="/dframe">dframe</a></p>', response.data)

            # a search for aking returns just that account
            query = {'s': 'aking'}
            response = client.get('/search/', query_string=query, follow_redirects=True)
            self.assertIn(b'<p>Results for: aking</p>', response.data)
            self.assertIn(b'<p><a href="/aking">aking</a></p>', response.data)
            self.assertNotIn(b'<p><a href="/abasco">abasco</a></p>', response.data)

            # a search for 'ki' will return all accounts that have 'ki' in their name
            query = {'s': 'ki'}
            response = client.get('/search/', query_string=query, follow_redirects=True)
            self.assertIn(b'<p>Results for: ki</p>', response.data)
            self.assertIn(b'<p><a href="/aking">aking</a></p>', response.data)
            self.assertIn(b'<p><a href="/tkimler">tkimler</a></p>', response.data)

            # a search containing an SQLi will be disarmed
            query = {'s': "' union all select password from users --"}
            response = client.get('/search/', query_string=query, follow_redirects=True)
            self.assertIn(b'<p>Results for: &#39; union all select passwor</p>', response.data)

            # a search containing malicious JS code will be disarmed (prevents Reflected XSS)
            query = {'s': '<script>alert(1)</script>'}
            response = client.get('/search/', query_string=query, follow_redirects=True)
            self.assertIn(b'<p>Results for: &#60;script&#62;alert(1)&#60;&#47;script&#62;</p>', response.data)

    def test_two_factor_authentication_success(self):
        with app.test_client() as client:
            # log in as a user that has 2fa enabled
            data = {'email': 'a.king@fakeemailservice.abcde',
                    'password': 'password_1'}
            client.post('/login/', data=data, follow_redirects=True)

            # the token is sent at this point, so we can pull it out of the database now. This is equivalent to the
            # user receiving the email and looking at the code.
            two_factor = ''
            with app.app_context():
                two_factor = db.get_two_factor(0)['code']  # we know aking is user 0

            # ensure the page is returned from a get request with no errors
            response = client.get('/confirmation/')
            self.assertIn(b'<h1>Confirmation</h1>', response.data)
            self.assertNotIn(b'invalid', response.data)
            self.assertNotIn(b'Incorrect', response.data)
            self.assertNotIn(b'failed', response.data)
            self.assertNotIn(b'expired', response.data)

            # test that entering a correct code results in authentication and passing to the index page
            data = {'code': two_factor}
            response = client.post('/confirmation/', data=data, follow_redirects=True)
            self.assertIn(b'<title>Index</title>', response.data)

            # the code should no longer be in the database
            with app.app_context():
                two_factor = db.get_two_factor(0)
                self.assertIsNone(two_factor)

    def test_two_factor_authentication_failure(self):
        with app.test_client() as client:
            # log in as a user that has 2fa enabled
            data = {'email': 'a.king@fakeemailservice.abcde',
                    'password': 'password_1'}
            client.post('/login/', data=data, follow_redirects=True)

            # ensure if the user inputs a code too short, it is rejected without changing the attempts remaining
            data = {'code': 'a'}
            response = client.post('/confirmation/', data=data, follow_redirects=True)
            self.assertIn(b'Code is invalid, please try again.', response.data)

            # ensure if the wrong code is entered, it reduces the number of tries remaining
            data = {'code': 'aaaaaa'}
            response = client.post('/confirmation/', data=data, follow_redirects=True)
            self.assertIn(b'Incorrect code. Attempts remaining 2', response.data)

            # adjust the timestamp of the code so the request gives an out-of-time error
            with app.app_context():
                ten_minutes_ago = datetime.now() - timedelta(minutes=10)
                time_formatted = ten_minutes_ago.strftime('%Y-%m-%d %H:%M:%S')  # remove the microseconds
                ten_minutes_ago = datetime.strptime(time_formatted, '%Y-%m-%d %H:%M:%S')
                query = "UPDATE twofactor SET timestamp=? WHERE user=0"
                db.update_db(query, (ten_minutes_ago,))

            response = client.post('/confirmation/', data=data, follow_redirects=True)
            self.assertIn(b'Code has expired. Please login again', response.data)

            # return the timestamp to now
            with app.app_context():
                now = datetime.now()
                now_formatted = now.strftime('%Y-%m-%d %H:%M:%S')  # remove the microseconds
                now = datetime.strptime(now_formatted, '%Y-%m-%d %H:%M:%S')
                query = "UPDATE twofactor SET timestamp=? WHERE user=0"
                db.update_db(query, (now,))

            # use up the remaining two attempts
            response = client.post('/confirmation/', data=data, follow_redirects=True)
            self.assertIn(b'Incorrect code. Attempts remaining 1', response.data)
            response = client.post('/confirmation/', data=data, follow_redirects=True)
            self.assertIn(b'Too many failed attempts', response.data)


if __name__ == '__main__':
    unittest.main()
