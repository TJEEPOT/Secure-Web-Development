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
        password = "oknowthisisareallylongpasswordthatnooneshouldeverhavebecauseitsjustannoyingatthispoint"
        self.assertIsNone(v.validate_password(password))

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
        self.assertIsNone(v.validate_username(""))  # smaller than minimum length

    def test_username_above_max(self):
        self.assertIsNone(v.validate_username("reallyovermaximumlengthusernamehere"))  # over max (32)

    def test_username_invalid_char(self):
        self.assertIsNone(v.validate_username("Username!"))  # unapproved special char

    def test_username_spaces(self):
        self.assertIsNone(v.validate_username("new user name"))  # unapproved spaces

    def test_odd_characters(self):
        self.assertIsNotNone(v.validate_username("Éeee"))
        self.assertIsNotNone(v.validate_username("用户名"))

    # email tests
    def test_email_short(self):
        email = "test@test.com"
        self.assertEqual(email, v.validate_email(email))

    def test_email_special_characters(self):
        email = "test-test.test@test.com"
        self.assertEqual("test-test.test@test.com", v.validate_email(email))

    def test_email_subdomain(self):
        email = "test@test.co.uk"
        self.assertEqual(email, v.validate_email(email))

    def test_email_invalid(self):
        email = "test-test.com"
        self.assertIsNone(v.validate_email(email))

    def test_email_sqli(self):
        email = "' or 1=1;--"
        self.assertIsNone(v.validate_email(email))

    # post tests
    def test_post_xss_length(self):
        self.assertIsNotNone(v.validate_text('<script>alert("xss");</script>'))

    def test_post_xss_above_length(self):
        max_length = 10
        overly_long_script = ""
        for x in range(max_length + 1):
            overly_long_script += "x"
        self.assertEqual('xxxxxxxxxx', v.validate_text(overly_long_script, max_length))

    def test_post_xss(self):
        self.assertNotEqual('<script>alert("xss");</script>', v.validate_text('<script>alert("xss");</script>'))

    def test_post_xss_character_encoding(self):
        self.assertEqual("&#38;&#60;&#62;&#34;&#39;&#37;&#42;&#43;&#44;&#45;&#47;&#59;&#61;&#94;&#124;",
                         v.validate_text("&<>\"'%*+,-/;=^|"))

    # search tests
    def test_search_xss_character_encoding(self):
        self.assertEqual("&#38;&#60;&#62;&#34;&#39;&#37;&#42;&#43;&#44;&#45;&#47;&#59;&#61;&#94;&#124;",
                         v.validate_text("&<>\"'%*+,-/;=^|"))

    def test_search_length_max(self):
        max_length = 10
        over_max_characters = ""
        for x in range(max_length + 1):
            over_max_characters += "x"
        self.assertEqual('xxxxxxxxxx', v.validate_text(over_max_characters, max_length))


    def test_parse_markup(self):
        test_string = "hello please [b]bold[/b] this text [b]thanks[/b] oh and [i]italicise[/i] " \
                      "this and [u]underline[/u] that but dont [b]bold this!"
        expected_output = "hello please <b>bold</b> this text <b>thanks</b> oh and <i>italicise</i> " \
                      "this and <u>underline</u> that but dont [b]bold this!"

        self.assertEqual(expected_output, v.parse_markup(test_string))
if __name__ == '__main__':
    unittest.main()