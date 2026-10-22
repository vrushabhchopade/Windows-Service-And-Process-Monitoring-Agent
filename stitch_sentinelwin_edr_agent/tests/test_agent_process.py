import unittest
import psutil
from agent.process_monitor import ProcessMonitor

class TestAgentProcessMonitor(unittest.TestCase):
    def setUp(self):
        self.monitor = ProcessMonitor()

    def test_process_scan(self):
        result = self.monitor.scan()
        self.assertIn("hostname", result)
        self.assertIn("processes", result)
        self.assertGreater(len(result["processes"]), 0)

    def test_lolbin_detection(self):
        flags = self.monitor._evaluate_suspicious_behavior(
            name="powershell.exe",
            parent_name="winword.exe",
            exe_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            cmdline="powershell.exe -ExecutionPolicy Bypass -e aW52b2tlLWV4cHJlc3Npb24=",
            in_temp=False,
            signed=True,
            cpu_percent=5.0,
            mem_percent=1.0
        )
        # Check if the suspicious parent-child chain or lolbin abuse is captured
        flag_types = [f["type"] for f in flags]
        self.assertIn("SUSPICIOUS_PARENT_CHILD", flag_types)

    def test_temp_execution(self):
        flags = self.monitor._evaluate_suspicious_behavior(
            name="malware.exe",
            parent_name="explorer.exe",
            exe_path="C:\\Users\\Public\\Temp\\malware.exe",
            cmdline="C:\\Users\\Public\\Temp\\malware.exe",
            in_temp=True,
            signed=False,
            cpu_percent=1.0,
            mem_percent=0.5
        )
        flag_types = [f["type"] for f in flags]
        self.assertIn("TEMP_DIRECTORY_EXECUTION", flag_types)

if __name__ == "__main__":
    unittest.main()
