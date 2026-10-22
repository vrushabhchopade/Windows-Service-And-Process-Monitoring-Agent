import unittest
from agent.registry_monitor import RegistryMonitor

class TestRegistryMonitor(unittest.TestCase):
    def setUp(self):
        self.monitor = RegistryMonitor()

    def test_registry_scan(self):
        res = self.monitor.scan_registry()
        self.assertIn("hostname", res)
        self.assertIn("entries", res)
        self.assertIn("anomalies", res)
        self.assertGreater(len(res["entries"]), 0)

    def test_new_persistence_detection(self):
        self.monitor.previous_values = {}
        # Test detection on a simulated new registry key
        res = self.monitor.scan_registry()
        # Find if the simulated malicious key triggered an anomaly
        anomaly_types = [a["type"] for a in res["anomalies"]]
        self.assertIn("REGISTRY_PERSISTENCE", anomaly_types)

if __name__ == "__main__":
    unittest.main()
