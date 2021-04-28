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
          27/04/2021 - v1.5 - Added helper / wrapper functions for encrypt and decrypt
          27/04/2021 - v1.6 - Removed generation of P and S boxes using encryption method, only sub-keys from P-boxes
                              are generated.

"""

__author__ = "Martin Siddons, Chris Sutton, Sam Humphreys, Steven Diep"
__copyright__ = "Copyright 2021, CMP-UG4"
__credits__ = ["Martin Siddons", "Chris Sutton", "Sam Humphreys", "Steven Diep"]
__version__ = "1.6"
__email__ = "yea18qyu@uea.ac.uk"
__status__ = "Development"  # or "Production"

import uuid
import constants

new_p_box = [None] * 18


class BlowyFishy:
    def __init__(self, key: str):
        self.key = key

        if len(key) < 4 or len(key) > 56 or not key:
            raise Exception("Key length must be between 32 - 448 bits long.")
        print(new_p_box)
        element = 0
        key_length = len(key)
        for i in range(len(constants.p_box)):
            input_key = (ord(key[element % key_length]) << 24) + (ord(key[(element + 1) % key_length]) << 16) + \
                        (ord(key[(element + 2) % key_length]) << 8) + ord(key[(element + 3) % key_length])
            new_p_box[i] = constants.p_box[i] ^ input_key
            element += 4
        print(new_p_box)

    def encrypt(self, lhs, rhs):
        """Encrypts a block size of 64 bit plain text using Blowfish
        :param int lhs: 32 Bits of left hand side
        :param int rhs: 32 Bits of right hand side

        :returns: int tuple of left and right hand side
        """
        for i in range(16):
            lhs ^= new_p_box[i]
            rhs ^= self.f_func(lhs)
            lhs, rhs = rhs, lhs
        lhs ^= new_p_box[16]
        rhs ^= new_p_box[17]
        lhs, rhs = rhs, lhs
        return lhs, rhs

    def decrypt(self, lhs, rhs):
        """Decrypts 64 bit cipher text using Blowfish
        :param int lhs: 32 Bits of left hand side
        :param int rhs: 32 Bits of right hand side

        :returns: int tuple of left and right hand side
        """
        for i in range(17, 1, -1):
            lhs ^= new_p_box[i]
            rhs ^= self.f_func(lhs)
            lhs, rhs = rhs, lhs
        lhs ^= new_p_box[1]
        rhs ^= new_p_box[0]
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
    def __init__(self, cipher, nonce: int):
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
            split_message_list.append(
                ''.join(format(ord(i), 'b').zfill(8) for i in message[text_block: text_block + 8]))

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
            character = [chr(int(formatted_binary[binary:binary + 8], 2)) for binary in
                         range(0, len(formatted_binary), 8)]
            for c in character:
                full_ciphertext += c
            counter += 1
        return full_ciphertext

    def ctr_decryption(self, cipher_message: str):
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


def encrypt(key, nonce, msg):
    """ Helper function for encryption

    :param key: Encryption key
    :param nonce: Nonce to use, generated from get_nonce()
    :param msg: Message to be encrypted
    :return: Encrypted message
    """
    # ensure validation for inputs rather than assume
    if type(key) is not bytes:
        key = bytes(key, "utf-8")
    if type(nonce) is not int:
        nonce = int(nonce)
    if type(msg) is not str:
        msg = str(msg)

    block_cipher = BlowyFishy(key)
    mode_ctr = CTR(block_cipher, nonce)
    encrypted_message = mode_ctr.ctr_encryption(msg)
    return encrypted_message


def decrypt(key, nonce, msg):
    """ Helper function for decryption

    :param key: Decryption key
    :param nonce: Nonce to use, generated from get_nonce()
    :param msg: Message to be decrypted
    :return: Decrypted message
    """
    # ensure validation for inputs rather than assume
    if type(key) is not bytes:
        key = bytes(key, "utf-8")
    if type(nonce) is not int:
        nonce = int(nonce)
    if type(msg) is not str:
        msg = str(msg)

    block_cipher = BlowyFishy(key)
    mode_ctr = CTR(block_cipher, nonce)
    decrypted_message = mode_ctr.ctr_decryption(msg)
    return decrypted_message
