#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""File to encrypt and decrypt by implementing the Blowfish cipher.

Module  : CMP6045-B - Developing a Secure Software, Assignment 2
File    : blowfish.py
Date    : Friday 9 April 2021
Desc.   : Simple encryption method done in Python.
History : 09/04/2021 - v1.0 - Create project file.
          10/04/2021 - v1.1 - Added BlowyFishy class.
          12/04/2021 - v1.2 - Added mode of operation for Blowfish cipher
          18/04/2021 - v1.3 - Used Counter mode
          18/04/2021 - v1.4 - Created unit tests

"""

__author__ = "Martin Siddons, Chris Sutton, Sam Humphreys, Steven Diep"
__copyright__ = "Copyright 2021, CMP-UG4"
__credits__ = ["Martin Siddons", "Chris Sutton", "Sam Humphreys", "Steven Diep"]
__version__ = "1.1"
__email__ = "yea18qyu@uea.ac.uk"
__status__ = "Development"  # or "Production"

import uuid
import constants


class BlowyFishy:
    def __init__(self, key):
        self.key = key

        if len(key) < 4 or len(key) > 56 or not key:
            raise Exception("Key length must be between 32 - 448 bits long.")

        new_p_box = [None] * 18
        key_length = len(key)
        for i in range(len(constants.p_box)):
            new_p_box[i] = constants.p_box[i] ^ ord(key[i % key_length])

        lhs, rhs = 0, 0
        # Changes all p-boxes
        for i in range(0, len(constants.p_box), 2):
            left_p, right_p = self.encrypt(lhs, rhs)
            new_p_box[i] = left_p
            new_p_box[i + 1] = right_p

        # Changes all s-boxes
        new_s_box = [[None] * 256] * 4
        for i in range(len(constants.s_box)):
            for j in range(0, len(constants.s_box[i]), 2):
                left_s, right_s = self.encrypt(lhs, rhs)
                new_s_box[i][j] = left_s
                new_s_box[i][j + 1] = right_s

    def encrypt(self, lhs, rhs):
        """Encrypts a block size of 64 bit plain text using Blowfish
        :param int lhs: 32 Bits of left hand side
        :param int rhs: 32 Bits of right hand side

        :returns: int tuple of left and right hand side
        """
        for i in range(16):
            lhs ^= constants.p_box[i]
            rhs ^= self.f_func(lhs)
            lhs, rhs = rhs, lhs
        lhs ^= constants.p_box[16]
        rhs ^= constants.p_box[17]
        lhs, rhs = rhs, lhs
        return lhs, rhs

    def decrypt(self, lhs, rhs):
        """Decrypts 64 bit cipher text using Blowfish
        :param int lhs: 32 Bits of left hand side
        :param int rhs: 32 Bits of right hand side

        :returns: int tuple of left and right hand side
        """
        for i in range(17, 1, -1):
            lhs ^= constants.p_box[i]
            rhs ^= self.f_func(lhs)
            lhs, rhs = rhs, lhs
        lhs ^= constants.p_box[1]
        rhs ^= constants.p_box[0]
        lhs, rhs = rhs, lhs
        return lhs, rhs

    def f_func(self, xor_data):
        """F-function splits 32 bit input into 4 parts

        :param int xor_data: 32 Bit left hand side

        :returns: F-function that will be XOR with right hand side
        """
        cp0 = (xor_data & 0xff000000) >> 24
        cp1 = (xor_data & 0x00ff0000) >> 16
        cp2 = (xor_data & 0x0000ff00) >> 8
        cp3 = xor_data & 0x000000ff

        f_out = (constants.s_box[0][cp0] + constants.s_box[1][cp1]) % constants.modulo
        f_out = constants.s_box[2][cp2] ^ f_out
        f_out = (constants.s_box[3][cp3] + f_out) % constants.modulo
        return f_out


class CTR(BlowyFishy):
    def __init__(self, cipher, nonce):
        self.cipher = cipher
        self.nonce = nonce

    def nonce_add_counter(self, counter):
        """Adds nonce and counter together to be encrypted
        :param int counter: Increments for every 64 bits

        :returns: int tuple of left and right hand side
        """
        lhs = self.nonce
        rhs = counter
        return self.cipher.encrypt(lhs, rhs)

    def ctr_encryption(self, message):
        """Divides plaintext into 64 bits
        :param str message: Plain text message

        :return: New string that is enciphered
        """

        # List of the message split into blocks
        split_message_list = []
        for text_block in range(0, len(message), 8):
            split_message_list.append(''.join(format(ord(i), 'b').zfill(8) for i in message[text_block: text_block + 8]))

        # Pad final block if it is not 64 bits
        if len(split_message_list[-1]) != 64:
            split_message_list[-1] = split_message_list[-1].ljust(64, '0')

        counter = 0
        full_ciphertext = ""
        for plain_text in split_message_list:
            # Returns as tuple, concatenate left and right

            lhs, rhs = self.nonce_add_counter(counter)
            block_cipher = (lhs << 32) + rhs
            ciphertext = int(plain_text, 2) ^ block_cipher
            formatted_binary = "{0:b}".format(ciphertext).zfill(64)
            character = [chr(int(formatted_binary[binary:binary+8], 2)) for binary in range(0, len(formatted_binary), 8)]
            for c in character:
                full_ciphertext += c
            counter += 1
        return full_ciphertext

    def ctr_decryption(self, cipher_message):
        """Decrypts message through using counter mode by calling ctr_encryption because of XOR
        :param str cipher_message: Bunch of gibberish that will be decrypted

        :returns: Deciphered message
        """
        msg = self.ctr_encryption(cipher_message)
        msg = msg.strip("\0")
        return msg


def get_nonce():
    """Creates 32 bit nonce
    :returns: Integer nonce
    """
    return uuid.uuid4().int & (1 << 32) - 1
