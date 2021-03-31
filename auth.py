# !/usr/bin/env python
# -*- coding: utf-8 -*-

""" Functions for the authorisation system
File    : auth.py
Date    : Thursday 25 March 2021
Desc.   : Handles functions for handling authorisation
History : 25/03/2021 - v1.0 - Load basic project file.
"""

import db
from numpy import random
from time import sleep

__author__ = "Martin Siddons, Chris Sutton, Sam Humphreys, Steven Diep"
__copyright__ = "Copyright 2021, CMP-UG4"
__credits__ = ["Martin Siddons", "Chris Sutton", "Sam Humphreys", "Steven Diep"]
__version__ = "1.0"
__email__ = "gny17hvu@uea.ac.uk"
__status__ = "Development"  # or "Production"


def authenticate_user(username, password):
    authenticated = False
    # time = current_time()
    # salt = db.get_salt(username)
    # if salt is not None:
    #     pass

    account = db.get_user(username)
    user_exists = len(account) > 0
    pass_match = db.get_password(account, password, username)
    # CS: Wait a random (small) amount of time before processing the authentication
    waittime = random.uniform(0.1, 0.5)
    sleep(waittime)
    if user_exists and pass_match:
        return account
    else:
        return None
