import unittest

from cyberapp import settings


class SettingsTest(unittest.TestCase):
    def test_settings_values_present(self):
        self.assertTrue(settings.DB_NAME)
        self.assertTrue(settings.ADMIN_USER)
        self.assertTrue(settings.ADMIN_PASS)
        self.assertTrue(settings.ANALYST_USER)
        self.assertTrue(settings.ANALYST_PASS)


if __name__ == "__main__":
    unittest.main()
