# !/usr/bin/env python
# -*- coding: utf-8 -*-

""" Email utility for the Flask server
File    : emailer.py
Date    : Thursday 01 April 2021
Desc.   : Class to handle email functions for blog
History : 01/04/2021 - v1.0 - Basic functions.
          06/04/2021 - v1.1 - Swapped out confidential details for EnvVars
"""

__author__ = "Martin Siddons, Chris Sutton, Sam Humphreys, Steven Diep"
__copyright__ = "Copyright 2021, CMP-UG4"
__credits__ = ["Martin Siddons", "Chris Sutton", "Sam Humphreys", "Steven Diep"]
__version__ = "1.1"
__email__ = "gny17hvu@uea.ac.uk"
__status__ = "Development"  # or "Production"

import os
import secrets
import smtplib
import string
import datetime
import time

from email.message import EmailMessage
from dotenv import load_dotenv

import db

load_dotenv(override=True)


class Emailer:
    def __init__(self):
        self._account_name = os.environ.get("UG_4_EMAIL")
        self._account_password = os.environ.get("UG_4_EPW")

    # Base function for sending emails
    def send_email(self, to_address: str, subject: str, message: str):
        mail_server = smtplib.SMTP('smtp.gmail.com', 587)  # This is using a TLS connection (not sure if allowed)
        mail_server.starttls()
        self._account_name += os.environ.get("UG_4_EMAIL_TYPE")
        mail_server.login(self._account_name, self._account_password)

        email_message = EmailMessage()
        email_message.set_content(message)
        email_message['Subject'] = subject
        email_message['From'] = self._account_name
        email_message['To'] = to_address

        mail_server.sendmail(self._account_name, to_address, message)
        mail_server.close()


def send_two_factor(uid, user_email):
    default_account = False

    # flag if the email address is one of the default accounts
    if user_email[-5:] == 'abcde':
        default_account = True

    # delete existing codes for this user
    db.del_two_factor(uid)

    # build and save a new code
    code = ""
    selection = string.ascii_letters
    for x in range(0, 6):
        code += secrets.choice(selection)  # TODO: secrets library used (not sure if allowed)
    db.set_two_factor(uid, str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')), code)
    # TODO: This was intended to be reusable by blog.py, creating and destroying is meh

    e = Emailer()
    message = "Your Two-Factor code for UG-4 Secure Blogging site is: " + code
    if default_account:
        print(db.get_two_factor(uid))
    else:
        e.send_email(user_email, "Blog Two Factor Code", message)

    return 'verify_code'


if __name__ == '__main__':
    time_now = datetime.datetime.now()
    time.sleep(3)
    time_now2 = datetime.datetime.now()
    print(time_now)
    print(time_now2)
    print(time_now2 - time_now)
    secs = (time_now2 - time_now).seconds
    mins = time_now2.minute

    print(secs >= 3)
    print(secs)
    print(mins)
