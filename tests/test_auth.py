import datetime
import unittest

import auth
import blog


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

    # for code coverage...
    def test__gen_s_box(self):
        s_box = [139, 157, 90, 231, 13, 22, 145, 230, 44, 66, 93, 181, 23, 2, 200, 232, 20, 225, 176, 151, 32, 92, 104,
                 55, 134, 149, 167, 247, 80, 33, 63, 248, 61, 114, 209, 172, 226, 19, 102, 236, 78, 190, 241, 244, 68,
                 128, 162, 189, 108, 0, 174, 60, 8, 224, 160, 187, 238, 110, 72, 95, 69, 234, 25, 141, 96, 217, 213,
                 120, 188, 15, 218, 179, 161, 36, 1, 196, 121, 152, 182, 175, 47, 49, 243, 53, 86, 245, 38, 100, 228,
                 79, 215, 10, 239, 197, 221, 77, 203, 210, 135, 201, 30, 91, 220, 155, 98, 26, 186, 150, 81, 57, 253,
                 251, 112, 242, 105, 73, 27, 94, 122, 4, 17, 6, 198, 75, 39, 184, 40, 136, 153, 206, 14, 177, 99, 171,
                 246, 115, 84, 124, 164, 212, 137, 111, 109, 106, 233, 54, 254, 222, 50, 113, 59, 168, 31, 193, 129,
                 58, 11, 118, 148, 144, 169, 205, 97, 204, 250, 116, 88, 107, 62, 163, 9, 158, 130, 227, 71, 64, 43,
                 52, 211, 183, 154, 82, 37, 195, 192, 18, 12, 117, 194, 65, 138, 165, 51, 199, 202, 24, 131, 87, 89,
                 127, 237, 126, 35, 147, 41, 123, 142, 173, 42, 214, 249, 252, 185, 16, 125, 229, 178, 219, 119, 208,
                 67, 132, 140, 159, 223, 83, 207, 156, 170, 85, 45, 48, 240, 76, 5, 29, 216, 180, 133, 146, 235, 21,
                 56, 191, 3, 101, 70, 166, 74, 143, 28, 7, 46, 34, 103, 255]
        self.assertEqual(s_box, auth._gen_s_box())

    def test_configure_app(self):
        app = blog.app
        auth.configure_app(app)
        self.assertEqual(datetime.timedelta(days=1), app.permanent_session_lifetime)


if __name__ == '__main__':
    unittest.main()
