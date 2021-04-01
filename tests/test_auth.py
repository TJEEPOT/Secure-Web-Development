import unittest
import auth


class MyTestCase(unittest.TestCase):
    def test_md2_hash_short(self):
        self.assertEqual("32ec01ec4a6dac72c0ab96fb34c0b5d1", auth.md2_hash("a"))

    def test_md2_hash_long(self):
        self.assertEqual("afa2ba75ed80271ee317071e0776c548",
                         auth.md2_hash("ThisIsAVeryLongPasswordWithNumbersAndSymbols123%$@~!é"))

    def test_ug4_hash_short(self):
        self.assertEqual("99f304b798199b1824285271f8fdfcb2f5c25e0e13136d2c066696b79cf3c6db"
                         "4d5bbcff7536649c8f21dd6356e76a4966046486230d4d5d0bccc89a200b582e",
                         auth.ug4_hash("a"))

    def test_ug4_hash_long(self):
        self.assertEqual("a1300241e7c05daa3e01b8c839ad220745da5b148ddfce4fc8176924afa3a054"
                         "efe575848f8eb4f92232135d1e427c8f79b17c6936b81e37c146574389fad4bc",
                         auth.ug4_hash("ThisIsAVeryLongPasswordWithNumbersAndSymbols123%$@~!é"))

    def test_ug4_hash_very_long(self):
        self.assertEqual("2c21a863e4e7771a2953a7aeb25ccc0ce084d48b666e3134b14c580083ca0f12"
                         "b2c680b52ee42d744e1c869bf2cb55602033634917c963e9afa58f7aee37c98e",
                         auth.ug4_hash("0123456789ThisIsAVeryLongPasswordDesignedToExtendBeyondABlock#!£$%^&*(){}"))

    def test_generate_salt(self):
        self.assertIsNotNone(auth.generate_salt())


if __name__ == '__main__':
    unittest.main()
