import unittest
from agent.service_monitor import ServiceMonitor

class TestAgentServiceMonitor(unittest.TestCase):
    def setUp(self):
        self.monitor = ServiceMonitor()

    def test_audit_services(self):
        result = self.monitor.audit_services()
        self.assertIn("hostname", result)
        self.assertIn("services", result)
        self.assertGreater(len(result["services"]), 0)

    def test_suspicious_service_detection(self):
        # Seed a fake previous service status list
        self.monitor.previous_services = {"WinDefend": "Running"}
        
        # Test detection of a suspicious service path
        test_services = [{
            "service_name": "SuspiciousSvc",
            "display_name": "Suspicious Persistence Service",
            "binary_path": "C:\\Users\\Public\\Temp\\backdoor.exe",
            "startup_type": "Automatic",
            "status": "Running",
            "service_account": "NT AUTHORITY\\SYSTEM",
            "description": "Vulnerable Persistence"
        }]
        
        # Monkeypatch the win32 query to return our test service
        self.monitor._query_win32_services = lambda: test_services
        
        result = self.monitor.audit_services()
        self.assertTrue(result["services"][0]["is_suspicious"])
        self.assertGreater(len(result["services"][0]["warnings"]), 0)

if __name__ == "__main__":
    unittest.main()
