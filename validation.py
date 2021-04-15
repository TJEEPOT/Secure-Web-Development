# !/usr/bin/env python
# -*- coding: utf-8 -*-

""" Helper Functions for validation
File    : validation.py
Date    : Monday 29 March 2021
Desc.   : Validation functions for use in other scripts - prevents circular referencing
History : 29/03/2021 - v1.0 - Load basic project file.
          06/04/2021 - v1.1 - Combine post and search functions, moved validate_two_factor() to auth.py
"""

__author__ = "Martin Siddons, Chris Sutton, Sam Humphreys, Steven Diep"
__copyright__ = "Copyright 2021, CMP-UG4"
__credits__ = ["Martin Siddons", "Chris Sutton", "Sam Humphreys", "Steven Diep"]
__version__ = "1.1"
__email__ = "gny17hvu@uea.ac.uk"
__status__ = "Development"  # or "Production"

import re

from dotenv import load_dotenv

load_dotenv(override=True)

min_password_length = 8  # OWASP auth guide
max_password_length = 64  # ^
min_username_length = 1  # As restricted by create_db.py
max_username_length = 32  # ^
max_post_length = 10000  # Arbitrary choices
max_search_length = max_username_length
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


# Passwords between 8-64 characters. Do not add additional validation here or it will break peoples existing passwords.
def validate_password(user_input: str):
    matched = re.match(r"^[\S]{8,64}$", user_input)
    return matched.string if matched else matched


# Minimum and maximum length, "_" and "-" only allowed special characters
def validate_username(user_input: str):
    matched = re.match(r"^[\w_-]{1,32}$", user_input)
    return matched.string if matched else matched


# This is a simple email address validation that is not compliant with all email addresses but matches most common.
# Rely on something else for primary email validation
# TODO redo
def validate_email(user_input: str):
    matched = re.match(r"^\w+(\w|.|-)*@\w+(.|\w)+\w", user_input)
    return matched.string if matched else matched


# Encode html characters, set maximum length
def validate_text(user_input: str, max_length=max_post_length):
    replaced_input = user_input
    for key, value in encoding_list.items():
        replaced_input = replaced_input.replace(key, value)
    replaced_input = re.sub(r"&(?!#\d*;)", "&#38;", replaced_input)  # replace & that are not part of previous replaces
    re_re_dict = {      # undo in the case of valid markup (simplest way)
        "b": "[/b]",
        "i": "[/i]",
        "u": "[/u]",
    }
    for key, value in re_re_dict.items():
        replaced_input = re.sub(rf"\[&#47;{key}\]", f"{value}", replaced_input)

    replaced_input = parse_markup(replaced_input)
    # break the string at the maximum length.
    return replaced_input if len(user_input) <= max_length else replaced_input[0:max_length]


# basic parsing for approved markup using [<command>] format
# TODO hook this up after all the merging with Martin's stuff
def parse_markup(user_input: str):
    change_dict = {
        "[b]": "<b>",
        "[/b]": "</b>",
        "[i]": "<i>",
        "[/i]": "</i>",
        "[u]": "<u>",
        "[/u]": "</u>"
    }
    partner_dict = {
        "[b]": "[/b]",
        "[i]": "[/i]",
        "[u]": "[/u]",
    }
    parsed_string = user_input
    for key, value in partner_dict.items():
        escaped_value = value.replace("[", "\[").replace("]", "\]") # for the regex format
        end_tag_matches = re.finditer(rf'{escaped_value}', parsed_string)
        end_spans = [end_match.span() for end_match in [*end_tag_matches]]
        parsed_string = parsed_string.replace(value, change_dict[value])
        parsed_string = parsed_string.replace(key, change_dict[key], len(end_spans))
    return parsed_string
