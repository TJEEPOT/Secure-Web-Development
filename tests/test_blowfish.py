import os
import time
import unittest

from dotenv import load_dotenv

import blowfish as b


class MyTestCase(unittest.TestCase):
    def test_full(self):
        message = "i love pushing to master"
        key = "thisisasecretkey"

        block_cipher = b.BlowyFishy(key)
        nonce = b.get_nonce()
        mode_ctr = b.CTR(block_cipher, nonce)

        encrypted_message = mode_ctr.ctr_encryption(message)
        decrypted_message = mode_ctr.ctr_decryption(encrypted_message)

        self.assertEqual(decrypted_message, message)

    def test_encryption(self):
        message = "i love pushing to master"
        key = "thisisasecretkey"

        block_cipher = b.BlowyFishy(key)
        nonce = b.get_nonce()
        mode_ctr = b.CTR(block_cipher, nonce)

        encrypted_message = mode_ctr.ctr_encryption(message)
        self.assertNotEqual(encrypted_message, message)

    def test_separate_objects(self):
        message = "i love pushing to master"
        key = "thisisasecretkey"

        block_cipher = b.BlowyFishy(key)
        nonce = b.get_nonce()
        mode_ctr = b.CTR(block_cipher, nonce)
        encrypted_message = mode_ctr.ctr_encryption(message)

        block_cipher_2 = b.BlowyFishy(key)
        mode_ctr_2 = b.CTR(block_cipher_2, nonce)
        decrypted_message = mode_ctr_2.ctr_decryption(encrypted_message)

        self.assertEqual(message, decrypted_message)

    def test_different_keys(self):
        message = "i love pushing to master"
        key = "thisisasecretkey"

        block_cipher = b.BlowyFishy(key)
        nonce = b.get_nonce()
        mode_ctr = b.CTR(block_cipher, nonce)
        encrypted_message = mode_ctr.ctr_encryption(message)

        key2 = "thisisanotherkey"
        block_cipher_2 = b.BlowyFishy(key2)
        mode_ctr_2 = b.CTR(block_cipher_2, nonce)
        decrypted_message = mode_ctr_2.ctr_decryption(encrypted_message)

        self.assertNotEqual(message, decrypted_message)

    def test_encrypt_decrypt_helpers(self):
        key = "thisisasecretkey"
        key = bytes(key, "utf-8")
        nonce = 4162467955
        message = "i love pushing to master"
        encrypted_msg = b.encrypt(key, nonce, message)
        print(encrypted_msg)

        incorrect_decrypt = b.decrypt("wrong key", nonce, encrypted_msg)
        self.assertNotEqual(message, incorrect_decrypt)

        incorrect_decrypt = b.decrypt(key, 123, encrypted_msg)
        self.assertNotEqual(message, incorrect_decrypt)

        decrypted_msg = b.decrypt(key, nonce, encrypted_msg)
        print(decrypted_msg)

        self.assertEqual(message, decrypted_msg)


if __name__ == '__main__':
    unittest.main()
