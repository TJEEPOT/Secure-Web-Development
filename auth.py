# !/usr/bin/env python
# -*- coding: utf-8 -*-

""" Functions for the authorisation system
File    : auth.py
Date    : Thursday 25 March 2021
Desc.   : Handles functions for handling authorisation
History : 25/03/2021 - v1.0 - Load basic project file.
"""

__author__ = "Martin Siddons, Chris Sutton, Sam Humphreys, Steven Diep"
__copyright__ = "Copyright 2021, CMP-UG4"
__credits__ = ["Martin Siddons", "Chris Sutton", "Sam Humphreys", "Steven Diep"]
__version__ = "1.0"
__email__ = "gny17hvu@uea.ac.uk"
__status__ = "Development"  # or "Production"

import time
import binascii
import db


# TODO: Rewrite this to ensure timing is the same (Issue 12) -MS
def authenticate_user(username, password):
    authenticated = False
    # time = current_time()
    # salt = db.get_salt(username)
    # if salt is not None:
    #     pass

    account = db.get_user(username)
    user_exists = len(account) > 0
    pass_match = db.get_password(account, password, username)

    if user_exists and pass_match:
        return account
    else:
        return None


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
    # Padding is always performed, even if the length of the message is already congruent to 0, modulo block_size.
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

    s = list(range(255))
    digits_pi = generate_pi()  # set up the generator for pi

    for i in range(2, 256):  # inclusive
        j = rand(i)
        tmp = s[j]
        s[j] = s[i - 1]
        s[i - 1] = tmp

    return s


if __name__ == "__main__":
    # print(_gen_s_box())
    # start = time.perf_counter()
    # for _ in range(10000):
    #     md2_hash("thisisapassword")
    # end = time.perf_counter()
    # print("time taken: ", end - start)
    print(md2_hash("1234567890ABCDEF"))
