from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from datetime import datetime, timedelta
import random

from apps.processes.models import ProcessLog
from apps.services.models import ServiceLog
from apps.eventlogs.models import WindowsEventLog
from apps.systemhealth.models import SystemHealthLog
from apps.alerts.models import Alert
from apps.ioc.models import IOCRule
from apps.investigation.models import InvestigationCase
from apps.settings_app.models import AgentSettings

class Command(BaseCommand):
    help = 'Seeds database with realistic initial endpoint telemetry and security alerts'

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS("Starting database seeding process..."))

        # Create Admin User
        if not User.objects.filter(username="admin").exists():
            User.objects.create_superuser("admin", "admin@sentinel.local", "admin123")
            self.stdout.write(self.style.SUCCESS("[+] Created superuser 'admin' (password: admin123)"))

        # Create Default Settings
        AgentSettings.objects.get_or_create(id=1, defaults={
            "monitoring_interval_seconds": 10,
            "cpu_threshold_percent": 85.0,
            "memory_threshold_percent": 90.0,
            "retention_days": 30
        })

        hostname = "WIN-EDR-AGENT-01"

        # Seed Processes
        sample_processes = [
            (4, 0, "System", "N/A", "SYSTEM", "C:\\Windows\\System32\\ntoskrnl.exe", "System", 0.1, 0.2, False, True),
            (688, 4, "smss.exe", "System", "SYSTEM", "C:\\Windows\\System32\\smss.exe", "smss.exe", 0.0, 0.1, False, True),
            (820, 688, "csrss.exe", "smss.exe", "SYSTEM", "C:\\Windows\\System32\\csrss.exe", "%SystemRoot%\\system32\\csrss.exe ObjectDirectory=\\Windows", 0.2, 0.4, False, True),
            (912, 688, "wininit.exe", "smss.exe", "SYSTEM", "C:\\Windows\\System32\\wininit.exe", "wininit.exe", 0.0, 0.2, False, True),
            (1024, 912, "services.exe", "wininit.exe", "SYSTEM", "C:\\Windows\\System32\\services.exe", "C:\\Windows\\system32\\services.exe", 0.5, 0.8, False, True),
            (1140, 912, "lsass.exe", "wininit.exe", "SYSTEM", "C:\\Windows\\System32\\lsass.exe", "C:\\Windows\\system32\\lsass.exe", 1.2, 2.5, False, True),
            (1450, 1024, "svchost.exe", "services.exe", "SYSTEM", "C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\system32\\svchost.exe -k DcomLaunch -p", 0.4, 1.1, False, True),
            (2130, 1024, "MsMpEng.exe", "services.exe", "SYSTEM", "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MsMpEng.exe", "MsMpEng.exe", 2.1, 4.5, False, True),
            (3420, 1024, "explorer.exe", "userinit.exe", "CORP\\jsmith", "C:\\Windows\\explorer.exe", "C:\\Windows\\Explorer.EXE", 1.8, 3.2, False, True),
            (4100, 3420, "chrome.exe", "explorer.exe", "CORP\\jsmith", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "chrome.exe --type=renderer", 8.4, 12.1, False, True),
            # Malicious Process Chains
            (5512, 3420, "winword.exe", "explorer.exe", "CORP\\jsmith", "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "WINWORD.EXE C:\\Users\\jsmith\\Downloads\\Invoice.docm", 1.5, 2.8, False, True),
            (5890, 5512, "powershell.exe", "winword.exe", "CORP\\jsmith", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -ExecutionPolicy Bypass -e aW52b2tlLWV4cHJlc3Npb24=", 12.5, 5.4, False, True),
            (6120, 3420, "cmd.exe", "explorer.exe", "CORP\\jsmith", "C:\\Windows\\System32\\cmd.exe", "cmd.exe /c start /min C:\\Users\\Public\\Temp\\update.exe", 0.5, 0.6, False, True),
            (6744, 6120, "mimikatz.exe", "cmd.exe", "SYSTEM", "C:\\Users\\Public\\Temp\\mimikatz.exe", "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit", 4.2, 1.8, True, False),
            (7100, 3420, "psexec.exe", "explorer.exe", "CORP\\jsmith", "C:\\Users\\Public\\psexec.exe", "psexec.exe \\\\DC01 -u admin -p Secret123 cmd.exe", 2.0, 1.1, True, False)
        ]

        for p in sample_processes:
            ProcessLog.objects.get_or_create(
                pid=p[0],
                hostname=hostname,
                defaults={
                    "ppid": p[1],
                    "name": p[2],
                    "parent_name": p[3],
                    "username": p[4],
                    "exe_path": p[5],
                    "cmdline": p[6],
                    "cpu_percent": p[7],
                    "memory_percent": p[8],
                    "is_in_temp": p[9],
                    "is_signed": p[10],
                    "status": "Running"
                }
            )
        self.stdout.write(self.style.SUCCESS(f"[+] Seeded {len(sample_processes)} Process records"))

        # Seed Services
        sample_services = [
            ("WinDefend", "Windows Defender Antivirus Service", "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MsMpEng.exe", "Automatic", "Running", "NT AUTHORITY\\LocalSystem", False),
            ("MpsSvc", "Windows Defender Firewall", "C:\\Windows\\System32\\mpssvc.dll", "Automatic", "Running", "NT Authority\\LocalService", False),
            ("EventLog", "Windows Event Log", "C:\\Windows\\System32\\wevtsvc.dll", "Automatic", "Running", "NT AUTHORITY\\LocalService", False),
            ("Sysmon64", "System Monitor Service", "C:\\Windows\\Sysmon64.exe", "Automatic", "Running", "NT AUTHORITY\\SYSTEM", False),
            ("RemoteUpdateSvc", "Remote System Update Helper", "C:\\Users\\Public\\Temp\\update_svc.exe -run", "Automatic", "Running", "NT AUTHORITY\\SYSTEM", True),
            ("PersistenceSvc", "Windows Application Helper", "C:\\Temp\\backdoor.exe", "Automatic", "Stopped", "NT AUTHORITY\\SYSTEM", True)
        ]

        for s in sample_services:
            ServiceLog.objects.get_or_create(
                service_name=s[0],
                hostname=hostname,
                defaults={
                    "display_name": s[1],
                    "binary_path": s[2],
                    "startup_type": s[3],
                    "status": s[4],
                    "service_account": s[5],
                    "is_suspicious": s[6],
                    "description": f"Windows Service {s[1]}"
                }
            )
        self.stdout.write(self.style.SUCCESS(f"[+] Seeded {len(sample_services)} Windows Service records"))

        # Seed Event Logs
        sample_eventlogs = [
            ("Security", 4688, "Microsoft-Windows-Security-Auditing", "Process Creation: Creator: winword.exe -> Child: powershell.exe", "HIGH", "T1059.001"),
            ("Security", 1102, "Microsoft-Windows-Security-Auditing", "The Security Audit log was cleared by user CORP\\jsmith", "CRITICAL", "T1070.001"),
            ("System", 7045, "Service Control Manager", "A service was installed in the system. Service Name: PersistenceSvc, Binary: C:\\Temp\\backdoor.exe", "HIGH", "T1543.003"),
            ("Security", 4625, "Microsoft-Windows-Security-Auditing", "An account failed to log on. Target User: Administrator, SubStatus: 0xc000006a", "MEDIUM", "T1110"),
            ("Sysmon", 10, "Microsoft-Windows-Sysmon", "LSASS memory read access attempt by C:\\Users\\Public\\Temp\\mimikatz.exe", "CRITICAL", "T1003.001"),
            ("Security", 4624, "Microsoft-Windows-Security-Auditing", "An account was successfully logged on. User: CORP\\jsmith", "INFO", "T1078")
        ]

        for e in sample_eventlogs:
            WindowsEventLog.objects.create(
                log_channel=e[0],
                event_id=e[1],
                source=e[2],
                message=e[3],
                severity=e[4],
                mitre_technique=e[5],
                computer=hostname,
                user="CORP\\jsmith"
            )
        self.stdout.write(self.style.SUCCESS(f"[+] Seeded {len(sample_eventlogs)} Windows Event Log records"))

        # Seed System Health
        for i in range(10):
            t = datetime.now() - timedelta(minutes=i*5)
            SystemHealthLog.objects.create(
                hostname=hostname,
                cpu_percent=round(random.uniform(15.0, 92.0), 1),
                ram_percent=round(random.uniform(40.0, 78.0), 1),
                disk_percent=38.5,
                disk_free_gb=320.4,
                network_sent_mb=round(random.uniform(10.0, 150.0), 1),
                network_recv_mb=round(random.uniform(50.0, 450.0), 1),
                top_cpu_processes=[{"name": "chrome.exe", "cpu_percent": 18.5}, {"name": "powershell.exe", "cpu_percent": 12.5}],
                top_ram_processes=[{"name": "chrome.exe", "ram_percent": 14.2}, {"name": "MsMpEng.exe", "ram_percent": 6.8}]
            )
        self.stdout.write(self.style.SUCCESS("[+] Seeded 10 System Health historical records"))

        # Seed IOC Rules
        sample_iocs = [
            ("ProcessName", "mimikatz.exe", "Known LSASS Credential Dumper", "CRITICAL"),
            ("ProcessName", "psexec.exe", "Sysinternals Remote Execution Tool", "HIGH"),
            ("FileName", "nc.exe", "Netcat command utility", "HIGH"),
            ("SHA256", "ef483293883a93647318536f901170d195e7d23d8c1c5304b77f8842410a51c4", "Cobalt Strike Beacon Hash", "CRITICAL"),
            ("IP", "185.220.101.5", "Tor Exit Node / C2 Server IP", "CRITICAL"),
            ("Domain", "malicious-c2-server.com", "Active Phishing / Command & Control Domain", "HIGH")
        ]

        for ioc in sample_iocs:
            IOCRule.objects.get_or_create(
                ioc_type=ioc[0],
                value=ioc[1],
                defaults={"description": ioc[2], "severity": ioc[3], "is_enabled": True}
            )
        self.stdout.write(self.style.SUCCESS(f"[+] Seeded {len(sample_iocs)} IOC rules"))

        # Seed Alerts
        sample_alerts = [
            ("Unauthorized Blacklisted Process: mimikatz.exe", "CRITICAL", "T1003.001 - OS Credential Dumping", "Blacklisted process 'mimikatz.exe' executed from C:\\Users\\Public\\Temp\\mimikatz.exe", 6744, "mimikatz.exe"),
            ("Suspicious Parent-Child Execution: winword.exe -> powershell.exe", "HIGH", "T1059.001 - Command and Scripting Interpreter", "Microsoft Word spawned encoded PowerShell execution. Cmdline: powershell.exe -ExecutionPolicy Bypass -e...", 5890, "powershell.exe"),
            ("Security Event ID 1102: Audit Log Cleared", "CRITICAL", "T1070.001 - Indicator Removal", "The Security Audit log was cleared by Administrator on host WIN-EDR-AGENT-01.", None, ""),
            ("Suspicious Service Path Executing from Temp", "HIGH", "T1543.003 - Windows Service Persistence", "Service 'PersistenceSvc' configured with binary path 'C:\\Temp\\backdoor.exe'", None, ""),
            ("Sysmon LSASS Memory Read Attempt", "CRITICAL", "T1003.001 - OS Credential Dumping", "LSASS process memory access granted to unprivileged binary C:\\Users\\Public\\Temp\\mimikatz.exe", 6744, "mimikatz.exe"),
            ("Resource Exhaustion: High CPU Usage Spiked to 92.5%", "MEDIUM", "T1496 - Resource Hijacking", "System CPU utilization exceeded 85% threshold. Top process: powershell.exe (PID 5890)", 5890, "powershell.exe")
        ]

        for a in sample_alerts:
            Alert.objects.get_or_create(
                title=a[0],
                hostname=hostname,
                defaults={
                    "severity": a[1],
                    "mitre_technique": a[2],
                    "description": a[3],
                    "pid": a[4],
                    "process_name": a[5],
                    "username": "CORP\\jsmith",
                    "recommendation": "Isolate endpoint, terminate suspicious process tree, and audit user logon sessions.",
                    "status": "New"
                }
            )
        self.stdout.write(self.style.SUCCESS(f"[+] Seeded {len(sample_alerts)} SOC Alert records"))

        # Seed Investigation Case
        InvestigationCase.objects.get_or_create(
            id=1,
            defaults={
                "title": "Incident INC-2026-0801: Credential Dumping & Macro Persistence",
                "hostname": hostname,
                "status": "Under Investigation",
                "assigned_analyst": "SOC Lead Analyst",
                "notes": "Phishing document Invoice.docm spawned encoded PowerShell execution followed by Mimikatz LSASS memory dumping."
            }
        )
        self.stdout.write(self.style.SUCCESS("[+] Seeded Investigation Case #1"))
        self.stdout.write(self.style.SUCCESS("Database seeding completed successfully!"))
