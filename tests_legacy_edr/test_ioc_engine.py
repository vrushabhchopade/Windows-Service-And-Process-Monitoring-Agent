import unittest
from agent.ioc_engine import IOCEngine

class TestIOCEngine(unittest.TestCase):
    def setUp(self):
        self.engine = IOCEngine()

    def test_ioc_process_name_match(self):
        sample_processes = [
            {"pid": 1234, "name": "mimikatz.exe", "exe_path": "C:\\Temp\\mimikatz.exe", "cmdline": "mimikatz.exe", "md5": "", "sha256": ""},
            {"pid": 5678, "name": "explorer.exe", "exe_path": "C:\\Windows\\explorer.exe", "cmdline": "explorer.exe", "md5": "", "sha256": ""}
        ]
        
        matches = self.engine.scan_processes(sample_processes)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["matched_process"], "mimikatz.exe")
        self.assertEqual(matches[0]["severity"], "CRITICAL")

    def test_ioc_hash_match(self):
        sample_processes = [
            {"pid": 4321, "name": "beacon.exe", "exe_path": "C:\\Temp\\beacon.exe", "cmdline": "beacon.exe", "md5": "", "sha256": "ef483293883a93647318536f901170d195e7d23d8c1c5304b77f8842410a51c4"}
        ]
        matches = self.engine.scan_processes(sample_processes)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["ioc_type"], "SHA256")

if __name__ == "__main__":
    unittest.main()
