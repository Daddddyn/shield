import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools import register_windows as R  # noqa: E402


class Registration(unittest.TestCase):
    def test_plan(self):
        e = R.plan('"C:\\Py\\pythonw.exe" "C:\\Shield\\shield.py"')
        keys = {(p, n): v for p, n, v in e}
        self.assertEqual(keys[(R.CAP + r"\URLAssociations", "https")], "ShieldURL")
        self.assertEqual(keys[(R.CAP + r"\URLAssociations", "http")], "ShieldURL")
        self.assertEqual(keys[(R.CAP + r"\FileAssociations", ".html")], "ShieldHTML")
        self.assertTrue(keys[(r"Software\Classes\ShieldURL\shell\open\command", "")].endswith('"%1"'))
        self.assertTrue(all(p.startswith("Software\\") for p, _, _ in e))       # current user only, nothing machine-wide

    def test_default_command(self):
        self.assertEqual(R.default_command("C:\\S\\Shield.exe"), '"C:\\S\\Shield.exe"')
        self.assertIn("shield.py", R.default_command())


if __name__ == "__main__":
    unittest.main()
