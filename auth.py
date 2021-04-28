# !/usr/bin/env python
# -*- coding: utf-8 -*-

""" Functions for the authorisation system.
File    : auth.py
Date    : Thursday 25 March 2021
Desc.   : Handles functions for handling authorisation.
History : 25/03/2021 - v1.0 - Load basic project file.
          31/03/2021 - v1.1 - Completed MD2 and UD4 hash implementations with helper functions and timer test harness
          31/03/2021 - v1.2 - Added function to generate salts
"""

__author__ = "Martin Siddons, Chris Sutton, Sam Humphreys, Steven Diep"
__copyright__ = "Copyright 2021, CMP-UG4"
__credits__ = ["Martin Siddons", "Chris Sutton", "Sam Humphreys", "Steven Diep"]
__version__ = "1.2"
__email__ = "gny17hvu@uea.ac.uk"
__status__ = "Development"  # or "Production"

import binascii
import datetime
import os
import random
import string

from dotenv import load_dotenv

import blowfish

load_dotenv(override=True)  # load the env vars from file into OS


def generate_salt():
    """ Generates a new salt randomly selected from a set of characters.

    :return: a unique 32 character salt
    """
    chars = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u",
             "v", "w", "x", "y", "z", "A", "B", "C", "E", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O",
             "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
             "_", "-"]
    salt = str()
    num_salt_chars = 32

    while num_salt_chars > 0:
        salt += chars[random.randrange(65)]  # randomly select one of the above chars
        num_salt_chars -= 1
    return salt


def md2_hash(password):
    """ A Python implementation of RFC-1319. https://www.rfc-editor.org/rfc/inline-errata/rfc1319.html.

    :param password: The password to be hashed
    :return: An MD2 hash of the given password
    """
    # 256-byte "random" permutation constructed from the digits of pi, used in step 2.
    # This substitution table was provided for us in RFC-1319
    s_box = [
        41,  46,  67,  201, 162, 216, 124, 1,   61,  54,  84,  161, 236, 240, 6,   19,
        98,  167, 5,   243, 192, 199, 115, 140, 152, 147, 43,  217, 188, 76,  130, 202,
        30,  155, 87,  60,  253, 212, 224, 22,  103, 66,  111, 24,  138, 23,  229, 18,
        190, 78,  196, 214, 218, 158, 222, 73,  160, 251, 245, 142, 187, 47,  238, 122,
        169, 104, 121, 145, 21,  178, 7,   63,  148, 194, 16,  137, 11,  34,  95,  33,
        128, 127, 93,  154, 90,  144, 50,  39,  53,  62,  204, 231, 191, 247, 151, 3,
        255, 25,  48,  179, 72,  165, 181, 209, 215, 94,  146, 42,  172, 86,  170, 198,
        79,  184, 56,  210, 150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4,   241,
        69,  157, 112, 89,  100, 113, 135, 32,  134, 91,  207, 101, 230, 45,  168, 2,
        27,  96,  37,  173, 174, 176, 185, 246, 28,  70,  97,  105, 52,  64,  126, 15,
        85,  71,  163, 35,  221, 81,  175, 58,  195, 92,  249, 206, 186, 197, 234, 38,
        44,  83,  13,  110, 133, 40,  132, 9,   211, 223, 205, 244, 65,  129, 77,  82,
        106, 220, 55,  200, 108, 193, 171, 250, 36,  225, 123, 8,   12,  189, 177, 74,
        120, 136, 149, 139, 227, 99,  232, 109, 233, 203, 213, 254, 59,  0,   29,  57,
        242, 239, 183, 14,  102, 88,  208, 228, 166, 119, 114, 248, 235, 117, 75,  10,
        49,  68,  80,  180, 143, 237, 31,  26,  219, 153, 141, 51,  159, 17,  131, 20
    ]

    block_size = 16  # 16 bytes or 128 bits
    password_bytes = bytearray(password, 'utf-8')  # turn the password into an array of bytes

    # Step 1: Append Padding Bytes
    # Padding is always performed, even if the length of the message is already congruent to 0 modulo block_size.
    # "i" bytes of value "i" are appended to the message
    padding = block_size - (len(password_bytes) % block_size)
    password_bytes += bytearray(padding for _ in range(padding))
    #  At this point the resulting message has a length that is an exact multiple of block_size bytes.

    # Step 2: Append Checksum
    # A block_size checksum of the message is appended to the result of the previous step.
    previous_check_byte = 0  # Keep track of the last byte written to checksum
    checksum = bytearray(0 for _ in range(block_size))  # Clear checksum: bytearray must be initialised before use

    # Process each 16-word block (16 bytes per block)
    for i in range(len(password_bytes) // block_size):  # Process each 16-word block
        for j in range(block_size):  # Checksum block i
            byte = password_bytes[i * block_size + j]
            checksum[j] ^= s_box[byte ^ previous_check_byte]  # Double XOR operation
            previous_check_byte = checksum[j]

    password_bytes += checksum

    # Step 3: Initialise MD Buffer
    buffer_size = 48  # 384 bits
    digest = bytearray([0 for _ in range(buffer_size)])

    # Step 4: Process message in 16-Byte blocks
    n_rounds = 18

    for i in range(len(password_bytes) // block_size):  # Process each 16-word block.
        for j in range(block_size):  # Copy block i into digest
            digest[block_size + j] = password_bytes[i * block_size + j]
            digest[2 * block_size + j] = digest[block_size + j] ^ digest[j]

        previous_hash_byte = 0  # set t to 0
        for j in range(n_rounds):
            for k in range(buffer_size):
                previous_hash_byte = digest[k] = digest[k] ^ s_box[previous_hash_byte]

            previous_hash_byte = (previous_hash_byte + j) % len(s_box)

    # Step 5: Output
    # The message digest produced as output is X[0 ... 15]. That is, we begin with digest[0], and end with digest[15].
    return binascii.hexlify(digest[:16]).decode('utf-8')


def ug4_hash(password, iterations=50):
    """ 512-bit hashing algorithm based on MD2. Iterates multiple times to ensure the hash is time-consuming.
    This will be secure enough for our needs, especially when salted and peppered.

    :param iterations: Number of iterations of the algorithm remaining to run through. This should remain as default.
    :param password: The password to be hashed
    :return: A 512-bit UG4 hash of the given password
    """
    s_box = [
        139, 157, 90,  231, 13,  22,  145, 230, 44,  66,  93,  181, 23,  2,   200, 232,
        20,  225, 176, 151, 32,  92,  104, 55,  134, 149, 167, 247, 80,  33,  63,  248,
        61,  114, 209, 172, 226, 19,  102, 236, 78,  190, 241, 244, 68,  128, 162, 189,
        108, 0,   174, 60,  8,   224, 160, 187, 238, 110, 72,  95,  69,  234, 25,  141,
        96,  217, 213, 120, 188, 15,  218, 179, 161, 36,  1,   196, 121, 152, 182, 175,
        47,  49,  243, 53,  86,  245, 38,  100, 228, 79,  215, 10,  239, 197, 221, 77,
        203, 210, 135, 201, 30,  91,  220, 155, 98,  26,  186, 150, 81,  57,  253, 251,
        112, 242, 105, 73,  27,  94,  122, 4,   17,  6,   198, 75,  39,  184, 40,  136,
        153, 206, 14,  177, 99,  171, 246, 115, 84,  124, 164, 212, 137, 111, 109, 106,
        233, 54,  254, 222, 50,  113, 59,  168, 31,  193, 129, 58,  11,  118, 148, 144,
        169, 205, 97,  204, 250, 116, 88,  107, 62,  163, 9,   158, 130, 227, 71,  64,
        43,  52,  211, 183, 154, 82,  37,  195, 192, 18,  12,  117, 194, 65,  138, 165,
        51,  199, 202, 24,  131, 87,  89,  127, 237, 126, 35,  147, 41,  123, 142, 173,
        42,  214, 249, 252, 185, 16,  125, 229, 178, 219, 119, 208, 67,  132, 140, 159,
        223, 83,  207, 156, 170, 85,  45,  48,  240, 76,  5,   29,  216, 180, 133, 146,
        235, 21,  56,  191, 3,   101, 70,  166, 74,  143, 28,  7,   46,  34,  103, 255
    ]  # this s-box was generated by _gen_s_box() which is based on pi similarly to MD2 but gives a different result.

    block_size = 64  # 64 bytes or 512 bits
    password_bytes = bytearray(password, 'utf-8')  # turn the password into an array of bytes

    # Step 1: Append Padding Bytes
    padding = block_size - (len(password_bytes) % block_size)
    password_bytes += bytearray(padding for _ in range(padding))

    # Step 2: Append Checksum
    previous_check_byte = 0  # Keep track of the last byte written to checksum
    checksum = bytearray(0 for _ in range(block_size))  # Clear checksum: bytearray must be initialised before use

    for i in range(len(password_bytes) // block_size):  # Process each block
        for j in range(block_size):  # Checksum block i
            byte = password_bytes[i * block_size + j]
            checksum[j] ^= s_box[byte ^ previous_check_byte]
            previous_check_byte = checksum[j]

    password_bytes += checksum

    # Step 3: Initialise MD Buffer
    buffer_size = 192  # 1536 bits or 3 times the size of the blocks.
    digest = bytearray([0 for _ in range(buffer_size)])

    # Step 4: Process message in 16-Byte blocks
    n_rounds = 77  # randomly chosen

    for i in range(len(password_bytes) // block_size):  # Process each 16-word block.
        for j in range(block_size):  # Copy block i into digest
            digest[block_size + j] = password_bytes[i * block_size + j]
            digest[2 * block_size + j] = digest[block_size + j] ^ digest[j]

        previous_hash_byte = 0  # set t to 0
        for j in range(n_rounds):
            for k in range(buffer_size):
                previous_hash_byte = digest[k] = digest[k] ^ s_box[previous_hash_byte]

            previous_hash_byte = (previous_hash_byte + j) % len(s_box)

    # Step 4b: Continue to Iterate
    # We now feed the found hash back into the algorithm to be iterated again, in order to increase the time to
    # generate it, increasing its security.
    found_hash = binascii.hexlify(digest[:64]).decode('utf-8')
    if iterations > 0:
        found_hash = ug4_hash(found_hash, iterations-1)

    # Step 5: Output
    return found_hash


# as given: https://crypto.stackexchange.com/questions/11935/how-is-the-md2-hash-function-s-table-constructed-from-pi
def _gen_s_box():
    """ Private function to generate a substitution box from 0-255 using the digits of pi.

    :return:  randomised substitution box.
    :rtype list[int]:
    """
    def generate_pi():
        # generate an infinite amount of pi digits:
        # https://stackoverflow.com/questions/9004789/1000-digits-of-pi-in-python
        q, r, t, k, m, x = 1, 0, 1, 1, 3, 3
        while True:
            if 4 * q + r - t < m * t:
                yield m
                q, r, t, k, m, x = 10 * q, 10 * (r - m * t), t, k, (10 * (3 * q + r)) // t - 10 * m, x
            else:
                q, r, t, k, m, x = q * k, (2 * q + r) * x, t * x, k + 1, (q * (7 * k + 2) + r * x) // (t * x), x + 2

    def rand(n):
        x = next(digits_pi)
        y = 10

        if n > 10:
            x = x * 10 + next(digits_pi)
            y = 100
        if n > 100:
            x = x * 10 + next(digits_pi)
            y = 1000

        if x < (n * (y / n)):  # division here is integer division
            return x % n
        else:
            return rand(n)  # x value is too large, don't use it

    s = list(range(256))
    digits_pi = generate_pi()  # set up the generator for pi

    for i in range(2, 256):
        j = rand(i)
        tmp = s[j]
        s[j] = s[i - 1]
        s[i - 1] = tmp

    return s


def configure_app(app):
    sek = bytes(os.environ["UG_4_SEK"], "utf-8")
    dbn = blowfish.decrypt(sek, 0, os.environ["UG_4_DBN"])
    app.config["ENV"] = blowfish.decrypt(sek, dbn, os.environ["UG_4_ENV"])
    app.config["DEBUG"] = blowfish.decrypt(sek, dbn, os.environ["UG_4_DEBUG"])
    app.config["TESTING"] = blowfish.decrypt(sek, dbn, os.environ["UG_4_TESTING"])
    app.secret_key = bytes(os.environ["UG_4_SECRET_KEY"], "utf-8")
    app.permanent_session_lifetime = datetime.timedelta(days=1)  # CS: Session lasts a day


def generate_code():
    code = ""
    selection = string.ascii_letters
    for x in range(0, 6):
        code += random.choice(selection)
    return code
