import unittest
import auth


class MyTestCase(unittest.TestCase):
    def test_md2_hash_short(self):
        self.assertEqual("32ec01ec4a6dac72c0ab96fb34c0b5d1", auth.md2_hash("a"))

    def test_md2_hash_long(self):
        self.assertEqual("afa2ba75ed80271ee317071e0776c548",
                         auth.md2_hash("ThisIsAVeryLongPasswordWithNumbersAndSymbols123%$@~!é"))


if __name__ == '__main__':
    unittest.main()
