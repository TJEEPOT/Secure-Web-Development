import unittest
import validation as v


class TestValidation(unittest.TestCase):

    # password tests
    def test_password_min(self):
        self.assertIsNotNone(v.validate_password("minimum1"))

    def test_password_max(self):
        self.assertIsNotNone(v.validate_password("thisissixtyfourcharactersihopeoknevermindreallyfaroffbutnowmaybe"))

    def test_password_punctuation(self):
        self.assertIsNotNone(v.validate_password("password123!%^&"))

    def test_password_spaces(self):
        self.assertIsNone(v.validate_password("pass word"))

    def test_password_below_min(self):
        self.assertIsNone(v.validate_password("pass"))

    def test_password_above_max(self):
        self.assertIsNone(
            v.validate_password(
                "oknowthisisareallylongpasswordthatnooneshouldeverhavebecauseitsjustannoyingatthispoint"))

    # username tests
    def test_username_min(self):
        self.assertIsNotNone(v.validate_username("min"))  # (3)

    def test_username_max(self):
        self.assertIsNotNone(v.validate_username("maximumlengthusernameeee"))  # (24)

    def test_username_caps(self):
        self.assertIsNotNone(v.validate_username("Capital"))

    def test_username_dash(self):
        self.assertIsNotNone(v.validate_username("joined-by-dash"))

    def test_username_underscore(self):
        self.assertIsNotNone(v.validate_username("with_underscore"))

    def test_username_below_min(self):
        self.assertIsNone(v.validate_username("1"))  # smaller than minimum length

    def test_username_above_max(self):
        self.assertIsNone(v.validate_username("overmaximumlengthusername"))  # over max (24)

    def test_username_invalid_char(self):
        self.assertIsNone(v.validate_username("Username!"))  # unapproved special char

    def test_username_spaces(self):
        self.assertIsNone(v.validate_username("new user name"))  # unapproved spaces

    def test_odd_characters(self):
        self.assertIsNotNone(v.validate_username("Éeee"))
        self.assertIsNotNone(v.validate_username("用户名"))

    # two factor tests

    def test_two_factor_min(self):
        self.assertEqual("abcdef",v.validate_two_factor("abcdef"))

    def test_two_factor_max(self):
        self.assertEqual("abcdef1234", v.validate_two_factor("abcdef1234"))

    def test_two_factor_below_min(self):
        self.assertEqual("abc", v.validate_two_factor("abc"))

    def test_two_factor_above_max(self):
        self.assertEqual("abcdef123456789", v.validate_two_factor("abcdef123456789"))

    def test_two_factor_invalid_characters(self):
        self.assertIsNone(v.validate_two_factor("` or 1=1;--"))

    def test_two_factor_caps(self):
        self.assertEqual("AbCdEf", v.validate_two_factor("AbCdEf"))



    # post tests

    def test_post_xss_length(self):
        self.assertIsNotNone(v.validate_post('<script>alert("xss");</script>'))

    def test_post_xss_above_length(self):
        max_length = 10000
        overly_long_script = ""
        for x in range(max_length + 1):
            overly_long_script += "x"
        self.assertIsNone(v.validate_post(overly_long_script))

    def test_post_xss(self):
        self.assertNotEqual('<script>alert("xss");</script>', v.validate_post('<script>alert("xss");</script>'))

    def test_post_xss_character_encoding(self):
        self.assertEqual("&#38;&#60;&#62;&#34;&#39;&#37;&#42;&#43;&#44;&#45;&#47;&#59;&#61;&#94;&#124;",
                         v.validate_post("&<>\"'%*+,-/;=^|"))

    # search tests

    def test_search_xss_character_encoding(self):
        self.assertEqual("&#38;&#60;&#62;&#34;&#39;&#37;&#42;&#43;&#44;&#45;&#47;&#59;&#61;&#94;&#124;",
                         v.validate_search("&<>\"'%*+,-/;=^|"))

    def test_search_length_max(self):
        max_length = 100
        over_max_characters = ""
        for x in range(max_length + 1):
            over_max_characters += "x"
        self.assertIsNone(v.validate_search(over_max_characters))


if __name__ == '__main__':
    unittest.main()
