import os
import unittest

from dotenv import load_dotenv

import blowfish as b


class MyTestCase(unittest.TestCase):
    def test_full(self):
        message = "i love pushing to master"
        key = "thisisasecretkey"
        key = bytes(key, "utf-8")

        block_cipher = b.BlowyFishy(key)
        nonce = b.get_nonce()
        mode_ctr = b.CTR(block_cipher, nonce)

        encrypted_message = mode_ctr.ctr_encryption(message)
        decrypted_message = mode_ctr.ctr_decryption(encrypted_message)

        self.assertEqual(decrypted_message, message)

    def test_encryption(self):
        message = "i love pushing to master"
        key = "thisisasecretkey"
        key = bytes(key, "utf-8")

        block_cipher = b.BlowyFishy(key)
        nonce = b.get_nonce()
        mode_ctr = b.CTR(block_cipher, nonce)

        encrypted_message = mode_ctr.ctr_encryption(message)

        self.assertNotEqual(encrypted_message, message)

    def test_separate_objects(self):
        message = "i love pushing to master"
        key = "thisisasecretkey"
        key = bytes(key, "utf-8")

        block_cipher = b.BlowyFishy(key)
        nonce = b.get_nonce()
        mode_ctr = b.CTR(block_cipher, nonce)
        encrypted_message = mode_ctr.ctr_encryption(message)

        block_cipher_2 = b.BlowyFishy(key)
        mode_ctr_2 = b.CTR(block_cipher_2, nonce)
        decrypted_message = mode_ctr_2.ctr_decryption(encrypted_message)

        self.assertEqual(message, decrypted_message)

    def test_encrypt_decrypt(self):
        key = "thisisasecretkey"
        nonce = 4162467955
        message = "i love pushing to master"
        encrypted_msg = b.encrypt(key, nonce, message)
        print(encrypted_msg)
        decrypted_msg = b.decrypt(key, nonce, encrypted_msg)
        print(decrypted_msg)

        self.assertEqual(message, decrypted_msg)

    # TODO: Remove before deployment
    # def test_encrypt_envar(self):
    #     key = bytes("茮ɽæ(ӛ7՝󱺎", "utf-8")
    #     nonce = 2105010172
    #     message = "DuJY7Ct-Y07HUpf7pvmAFw"
    #     encrypted_msg = b.encrypt(key, nonce, message)
    #     print(encrypted_msg)
    #     print(bytes(encrypted_msg, "utf-8"))
    #
    # def test_decrypt_envar(self):
    #     load_dotenv(override=True)
    #     key = bytes("茮ɽæ(ӛ7՝󱺎", "utf-8")
    #     nonce = 2105010172
    #     message = "4ÃÂF_8¸Ëlf¼W¶æ¸9¾SP"
    #     decrypted_msg = b.decrypt(key, nonce, message)
    #     print(bytes(decrypted_msg, "utf-8"))
    #     print(decrypted_msg)
    #
    #     print(os.environ.get('UG_4_PW'))
    #     print(b.decrypt(key, nonce, os.environ.get('UG_4_PW')))


if __name__ == '__main__':
    unittest.main()
