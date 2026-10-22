import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

class TestAlertEngine(unittest.TestCase):
    def setUp(self):
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
        import django
        django.setup()
        from apps.alerts.models import Alert
        self.AlertModel = Alert

    def test_alert_creation_properties(self):
        # Create a sample alert in the db
        alert = self.AlertModel.objects.create(
            title="Suspicious Rundll32 Execution",
            severity="CRITICAL",
            hostname="TEST-HOST-01",
            username="CORP\\testuser",
            description="Rundll32 executed with blank command line parameters.",
            mitre_technique="T1218.011",
            recommendation="Analyze parent process and network connection trends.",
            source_module="ProcessMonitor",
            status="New"
        )
        
        self.assertIsNotNone(alert.id)
        self.assertEqual(alert.severity, "CRITICAL")
        self.assertEqual(alert.status, "New")
        
        # Clean up
        alert.delete()

if __name__ == "__main__":
    unittest.main()
