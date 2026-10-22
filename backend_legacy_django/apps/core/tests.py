from django.test import TestCase, Client
from django.contrib.auth.models import User
from apps.processes.models import ProcessLog
from apps.alerts.models import Alert
from apps.ioc.models import IOCRule

class SentinelAPITests(TestCase):
    def setUp(self):
        self.client = Client()
        self.admin = User.objects.create_superuser("test_admin", "admin@sentinel.local", "secure_pass123")

    def test_dashboard_status(self):
        # Unauthenticated redirects to login in real EDR, let's check ok response
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)

    def test_process_telemetry_ingestion(self):
        payload = {
            "hostname": "TEST-HOST",
            "processes": [
                {
                    "pid": 9999,
                    "ppid": 4,
                    "name": "malware_test.exe",
                    "parent_name": "System",
                    "username": "SYSTEM",
                    "exe_path": "C:\\Users\\Public\\Temp\\malware_test.exe",
                    "cmdline": "malware_test.exe -run",
                    "cpu_percent": 1.5,
                    "memory_percent": 0.5,
                    "md5": "d41d8cd98f00b204e9800998ecf8427e",
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "is_in_temp": True,
                    "is_signed": False,
                    "status": "Running",
                    "suspicious_flags": [
                        {
                            "type": "TEMP_DIRECTORY_EXECUTION",
                            "severity": "HIGH",
                            "description": "Executable running from Temp",
                            "mitre": "T1036.005"
                        }
                    ]
                }
            ],
            "ioc_matches": []
        }

        resp = self.client.post(
            "/api/v1/telemetry/process/",
            data=payload,
            content_type="application/json"
        )
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(ProcessLog.objects.filter(hostname="TEST-HOST").count(), 1)
        
        # Verify alert was auto-created from suspicious flag
        self.assertEqual(Alert.objects.filter(hostname="TEST-HOST").count(), 1)
        alert = Alert.objects.get(hostname="TEST-HOST")
        self.assertEqual(alert.severity, "HIGH")

    def test_ioc_csv_import(self):
        csv_data = (
            "ioc_type,value,severity,description\n"
            "ProcessName,hacker.exe,CRITICAL,Malicious hacking tool\n"
            "IP,1.2.3.4,HIGH,Suspicious target IP\n"
        )
        import io
        file_obj = io.BytesIO(csv_data.encode('utf-8'))
        file_obj.name = "threat_intel.csv"

        resp = self.client.post(
            "/api/v1/ioc/import-csv/",
            {"file": file_obj}
        )
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(IOCRule.objects.filter(ioc_type="ProcessName").count(), 1)
        self.assertEqual(IOCRule.objects.get(ioc_type="IP").value, "1.2.3.4")
