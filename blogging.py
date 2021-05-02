# !/usr/bin/env python
# -*- coding: utf-8 -*-

""" Logger for blog events
File    : blogging.py
Date    : Saturday 03 April 2021
Desc.   : Logging wrapper functions for logging various blog events
History : 03/04/2021 - v1.0 - Basic functions.
"""

__author__ = "Martin Siddons, Chris Sutton, Sam Humphreys, Steven Diep"
__copyright__ = "Copyright 2021, CMP-UG4"
__credits__ = ["Martin Siddons", "Chris Sutton", "Sam Humphreys", "Steven Diep"]
__version__ = "1.0"
__email__ = "gny17hvu@uea.ac.uk"
__status__ = "Development"  # or "Production"

import logging
import datetime
import os

previous_date = None


def create_dir_if_not_exist():
    if not os.path.isdir("logs/"):
        os.mkdir('logs/')


def get_file_location():
    create_dir_if_not_exist()
    base = "logs/"
    date = get_date()
    full_location = base + date + ".log"
    return full_location


def get_date():
    date = datetime.date.today()
    return date.strftime('%Y-%m-%d')


def config_logger():
    try:
        logging.basicConfig(filename=get_file_location(),
                            format='%(asctime)s : %(levelname)s : %(message)s',
                            level=logging.INFO)
    except:
        # incase something weird happens with the file system
        logging.basicConfig(format='%(asctime)s : %(levelname)s : %(message)s',
                            level=logging.INFO)

    global previous_date
    previous_date = get_date()


def log_user_activity_happy(user_id: str, ip: str, activity: str):
    if previous_date is not get_date():
        config_logger()
    logging.info(f'[User: {user_id},{ip}, {activity}]')


def log_user_activity_unhappy(user_id: str, ip: str, activity: str):
    if previous_date is not get_date():
        config_logger()
    logging.warning(f'[User: {user_id}, {ip}, {activity}]')


def log_this(log_me: str):
    logging.info(log_me)


if __name__ == '__main__':
    log_user_activity_unhappy("0", "100.000.000.000", "oops")
    log_user_activity_happy("0", "100.001.000.000", "yay")
