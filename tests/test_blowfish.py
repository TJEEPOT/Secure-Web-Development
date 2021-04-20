import unittest
import blowfish as b


class MyTestCase(unittest.TestCase):
    def test_full(self):
        message = "i love pushing to master"
        key = "thisisasecretkey"

        block_cipher = b.BlowyFishy(key)
        mode_ctr = b.CTR(block_cipher)

        encrypted_message = mode_ctr.ctr_encryption(message)
        decrypted_message = mode_ctr.ctr_decryption(encrypted_message)

        self.assertEqual(decrypted_message, message)

    def test_encryption(self):
        message = "i love pushing to master"
        key = "thisisasecretkey"

        block_cipher = b.BlowyFishy(key)
        mode_ctr = b.CTR(block_cipher)

        encrypted_message = mode_ctr.ctr_encryption(message)

        self.assertNotEqual(encrypted_message, message)

if __name__ == '__main__':
    unittest.main()
