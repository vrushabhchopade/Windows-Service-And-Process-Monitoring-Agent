import unittest
from agent.wmi_monitor import WMIMonitor

class TestWMIMonitor(unittest.TestCase):
    def setUp(self):
        self.monitor = WMIMonitor()

    def test_wmi_event_collection(self):
        res = self.monitor.collect_events()
        self.assertIn("hostname", res)
        self.assertIn("events", res)
        self.assertIn("anomalies", res)

    def test_shadowcopy_deletion_detection(self):
        # Manually inject VSS shadowcopy deletion command event
        self.monitor.captured_events.append({
            "event_type": "PROCESS_CREATION",
            "pid": 5544,
            "ppid": 3420,
            "name": "wmic.exe",
            "cmdline": "wmic.exe shadowcopy delete /nointeractive",
            "timestamp": ""
        })
        res = self.monitor.collect_events()
        self.assertEqual(len(res["anomalies"]), 1)
        self.assertEqual(res["anomalies"][0]["type"], "VSS_SHADOW_DELETION")

if __name__ == "__main__":
    unittest.main()
