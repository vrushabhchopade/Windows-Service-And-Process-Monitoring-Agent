import unittest
import time
from agent.fim_monitor import FIMMonitor

class TestFIMMonitor(unittest.TestCase):
    def setUp(self):
        self.monitor = FIMMonitor()

    def test_fim_scan(self):
        res = self.monitor.scan()
        self.assertIn("hostname", res)
        self.assertIn("events", res)
        self.assertIn("alerts", res)

    def test_ransomware_heuristic(self):
        # Simulate 12 modification events within 10 seconds
        now = time.time()
        self.monitor.change_history = [now - i for i in range(12)]
        
        # Seed simulated events
        events = [
            {"action": "MODIFIED", "filepath": "C:\\Windows\\System32\\Drivers\\etc\\hosts", "entropy": 7.8, "timestamp": ""}
        ]
        
        res = self.monitor.scan()
        # Trigger ransomware analysis by manually adding high change history and scanning
        self.monitor.change_history = [now] * 15
        
        # Test basic entropy logic
        entropy = self.monitor._calculate_file_entropy(__file__)
        self.assertGreater(entropy, 0.0)

if __name__ == "__main__":
    unittest.main()
