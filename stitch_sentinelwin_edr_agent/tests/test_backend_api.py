import os
import sys
import unittest
from pathlib import Path

# Add project directories to python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

class TestBackendAPIWrapper(unittest.TestCase):
    def test_run_django_tests(self):
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
        import django
        django.setup()
        
        from django.core.management import call_command
        failures = call_command("test", "apps.core.tests", verbosity=1, interactive=False)
        self.assertTrue(failures in [0, None], f"Django test suite failed with {failures} errors")

if __name__ == "__main__":
    unittest.main()
