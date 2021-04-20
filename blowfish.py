#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""File to encrypt and decrypt by implementing the Blowfish cipher.

Module  : CMP6045-B - Developing a Secure Software, Assignment 2
File    : blowfish.py
Date    : Friday 9 April 2021
Desc.   : Simple encryption method done in Python.
History : 09/04/2021 - v1.0 - Create project file.
          10/04/2021 - v1.1 - Added BlowyFishy class.


"""

import uuid
import constants


class BlowyFishy:
    def __init__(self, key):
        self.key = key

        if len(key) < 4 or len(key) > 56 or not key:
            raise Exception("Key length must be between 32 - 448 bits long.")

        key_length = len(key)
        for i in range(len(constants.p_box)):
            constants.p_box[i] ^= ord(key[i % key_length])

        lhs, rhs = 0, 0
        # Changes all p-boxes
        for i in range(0, len(constants.p_box), 2):
            left_p, right_p = self.encrypt(lhs, rhs)
            constants.p_box[i] = left_p
            constants.p_box[i + 1] = right_p

        # Changes all s-boxes
        for i in range(len(constants.s_box)):
            for j in range(0, len(constants.s_box[i]), 2):
                left_s, right_s = self.encrypt(lhs, rhs)
                constants.s_box[i][j] = left_s
                constants.s_box[i][j + 1] = right_s

    def encrypt(self, lhs, rhs):
        """Encrypts plain text using Blowfish
        :param
        :param
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
        """Decrypts cipher text using Blowfish
        :param
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

        :param int xor_data:
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
    # Generated 64 bit integer nonce
    def __init__(self, cipher, nonce=uuid.uuid4().int & (1 << 32) - 1):
        self.cipher = cipher
        self.nonce = nonce

    def nonce_add_counter(self, counter):
        """Adds nonce and counter together to be encrypted
        :param
        """
        #nonce_plus_counter = (self.nonce << 32) + counter
        # Turns integer into 64 bit binary representation
        #bit_rep = "{0:b}".format(nonce_plus_counter)
        # 64 bit is split in half, left and right hand side
        #lhs, rhs = int(bit_rep[0:len(bit_rep) // 2]), int(bit_rep[(len(bit_rep) // 2):])
        lhs = self.nonce
        rhs = counter
        return self.cipher.encrypt(lhs, rhs)

    def ctr_encryption(self, message):
        """Divides plaintext into 64 bits
        :param

        :return:
        """
        #message_length = len(message)
        # Block size is 64 bits and each character in a message contains 8 bits
        #leftover_bytes = message_length % 8
        # Mark where the message furthest extends before possible padding
        #max_block = message_length - leftover_bytes

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

    def ctr_decryption(self, message):
        msg = self.ctr_encryption(message)
        msg = msg.strip("\0")
        return msg


def main():
    """key = "thisisasecretkey"
    cipher = BlowyFishy(key)

    left, right = 0b01101001001000000110110001101111, 0b000000000000000000000000000000
    print(f"Left: {left}, Right: {right}")
    print("Encrypting:")
    cl, cr = cipher.encrypt(left, right)
    print(cl, cr)

    print("Decrypting:")
    dl, dr = cipher.decrypt(cl, cr)
    print(dl, dr)"""

    key = "thisisasecretkey"
    block_cipher = BlowyFishy(key)

    mode_ctr = CTR(block_cipher)
    cipher = mode_ctr.ctr_encryption("i love cclove cors and sheep")
    print("Cipher text:")
    print(cipher)
    decipher = mode_ctr.ctr_decryption(cipher)
    print("Decipher text:")
    print(decipher)

    assert "i love cclove cors and sheep" == decipher


if __name__ == '__main__':
    main()
