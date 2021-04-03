# !/usr/bin/env python
# -*- coding: utf-8 -*-

""" Helper Functions for validation
File    : validation.py
Date    : Monday 29 March 2021
Desc.   : Validation functions for use in other scripts - prevents circular referencing
History : 29/03/2021 - v1.0 - Load basic project file.
"""

__author__ = "Martin Siddons, Chris Sutton, Sam Humphreys, Steven Diep"
__copyright__ = "Copyright 2021, CMP-UG4"
__credits__ = ["Martin Siddons", "Chris Sutton", "Sam Humphreys", "Steven Diep"]
__version__ = "1.0"
__email__ = "gny17hvu@uea.ac.uk"
__status__ = "Development"  # or "Production"

import re

min_password_length = 8  # OWASP auth guide
max_password_length = 64  # ^
min_username_length = 1  # As restricted by create_db.py
max_username_length = 32  # ^
max_post_length = 10000  # Arbitrary choices
max_search_length = 100  # ^
encoding_list = {
    #    "&": "&#38;",
    ";": "&#59;",
    "<": "&#60;",
    ">": "&#62;",
    "\"": "&#34;",
    "'": "&#39;",
    "%": "&#37;",
    "*": "&#42;",
    "+": "&#43;",
    ",": "&#44;",
    "-": "&#45;",
    "/": "&#47;",
    "=": "&#61;",
    "^": "&#94;",
    "|": "&#124;"
}


# passwords between 8-64 characters
def validate_password(user_input: str):
    matched = re.match(r"^[\S]{8,64}$", user_input)
    return matched


# minimum and maximum length, "_" and "-" only allowed special characters
def validate_username(user_input: str):
    matched = re.match(r"^[\w_-]{3,24}$", user_input)
    return matched


# alphanumeric + caps, 6-10
def validate_two_factor(user_input: str):
    matched = re.match(r"^[\w]{6,10}$", user_input)
    return matched


# encode html characters, set maximum length
def validate_post(user_input: str):
    replaced_input = user_input
    for key, value in encoding_list.items():
        replaced_input = replaced_input.replace(key, value)
    replaced_input = re.sub(r"&(?!#\d*;)", "&#38;", replaced_input)  # replace & that are not part of previous replaces
    post_length = len(user_input)  # just checking max since no minimum
    return replaced_input if post_length <= max_post_length else None


# same as post but shorter limit for now
def validate_search(user_input: str):
    replaced_input = user_input
    for key, value in encoding_list.items():
        replaced_input = replaced_input.replace(key, value)
    replaced_input = re.sub(r"&(?!#\d*;)", "&#38;", replaced_input)  # replace & that are not part of previous replaces
    search_length = len(user_input)  # just checking max since no minimum
    return replaced_input if search_length <= max_search_length else None
