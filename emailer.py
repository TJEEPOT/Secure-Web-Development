# !/usr/bin/env python
# -*- coding: utf-8 -*-

""" Email utility for the Flask server
File    : emailer.py
Date    : Thursday 01 April 2021
Desc.   : Class to handle email functions for blog
History : 01/04/2021 - v1.0 - Basic functions.
"""

__author__ = "Martin Siddons, Chris Sutton, Sam Humphreys, Steven Diep"
__copyright__ = "Copyright 2021, CMP-UG4"
__credits__ = ["Martin Siddons", "Chris Sutton", "Sam Humphreys", "Steven Diep"]
__version__ = "1.0"
__email__ = "gny17hvu@uea.ac.uk"
__status__ = "Development"  # or "Production"

import smtplib
from email.message import EmailMessage

import datetime
import time

class Emailer:

    def __init__(self):
        self._credential_file_location = "emailcreds.txt"    # TODO store creds in DB?
        try:
            with open(self._credential_file_location) as file:
                creds = file.read().split(",", 1)  # Credentials file must be in the form 'username,password'
                self._account_name = creds[0]
                self._account_password = creds[1]
        except FileNotFoundError:
            print("Email login file not found")

    # Base function for sending emails
    def send_email(self, to_address: str, subject: str, message: str):
        mail_server = smtplib.SMTP('smtp.gmail.com', 587)  # This is using a TLS connection (not sure if allowed)
        mail_server.starttls()
        mail_server.login(self._account_name, self._account_password)
        email_message = EmailMessage()
        email_message.set_content(message)
        email_message['Subject'] = subject
        email_message['From'] = self._account_name
        email_message['To'] = to_address
        mail_server.sendmail(self._account_name, to_address, message)
        mail_server.close()


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