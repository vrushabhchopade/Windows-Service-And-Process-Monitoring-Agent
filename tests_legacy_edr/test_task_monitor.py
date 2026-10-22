import unittest
from unittest.mock import patch
from agent.task_monitor import TaskMonitor

class TestTaskMonitor(unittest.TestCase):
    def setUp(self):
        self.monitor = TaskMonitor()

    @patch("platform.system", return_value="Linux")
    def test_scheduled_task_scan(self, mock_system):
        res = self.monitor.query_scheduled_tasks()
        self.assertIn("hostname", res)
        self.assertIn("tasks", res)
        self.assertIn("anomalies", res)
        self.assertGreater(len(res["tasks"]), 0)

    @patch("platform.system", return_value="Linux")
    def test_persistence_task_detection(self, mock_system):
        res = self.monitor.query_scheduled_tasks()
        # The fallback loader injects a persistence task running from temp
        anomalies = res["anomalies"]
        self.assertGreater(len(anomalies), 0)
        self.assertEqual(anomalies[0]["type"], "SUSPICIOUS_SCHEDULED_TASK")

if __name__ == "__main__":
    unittest.main()

