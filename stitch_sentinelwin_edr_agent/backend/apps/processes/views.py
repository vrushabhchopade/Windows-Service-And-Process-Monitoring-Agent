from django.shortcuts import render
from rest_framework import viewsets, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from apps.processes.models import ProcessLog
from apps.processes.serializers import ProcessLogSerializer
from apps.alerts.models import Alert

class ProcessLogViewSet(viewsets.ModelViewSet):
    queryset = ProcessLog.objects.all()
    serializer_class = ProcessLogSerializer
    permission_classes = [permissions.AllowAny]

    def get_queryset(self):
        qs = super().get_queryset()
        hostname = self.request.query_params.get("hostname")
        search = self.request.query_params.get("search")
        if hostname:
            qs = qs.filter(hostname=hostname)
        if search:
            qs = qs.filter(name__icontains=search) | qs.filter(cmdline__icontains=search)
        return qs

class ProcessTelemetryIngestView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        hostname = request.data.get("hostname", "WIN-EDR-AGENT-01")
        processes_data = request.data.get("processes", [])
        ioc_matches = request.data.get("ioc_matches", [])

        created_objs = []
        for p in processes_data:
            obj = ProcessLog(
                pid=p.get("pid"),
                ppid=p.get("ppid"),
                name=p.get("name", "unknown"),
                parent_name=p.get("parent_name", "N/A"),
                username=p.get("username", "SYSTEM"),
                exe_path=p.get("exe_path", ""),
                cmdline=p.get("cmdline", ""),
                create_time=p.get("create_time"),
                cpu_percent=p.get("cpu_percent", 0.0),
                memory_percent=p.get("memory_percent", 0.0),
                md5=p.get("md5", ""),
                sha256=p.get("sha256", ""),
                is_in_temp=p.get("is_in_temp", False),
                is_signed=p.get("is_signed", True),
                status=p.get("status", "Running"),
                hostname=hostname
            )
            created_objs.append(obj)

            # Evaluate suspicious flags to auto-create alerts
            flags = p.get("suspicious_flags", [])
            for flag in flags:
                Alert.objects.create(
                    title=f"Suspicious Process: {p.get('name')}",
                    severity=flag.get("severity", "HIGH"),
                    hostname=hostname,
                    username=p.get("username", "SYSTEM"),
                    description=flag.get("description"),
                    mitre_technique=flag.get("mitre", "T1059"),
                    recommendation=f"Terminate process PID {p.get('pid')} and quarantine executable {p.get('exe_path')}",
                    source_module="ProcessMonitor",
                    pid=p.get("pid"),
                    process_name=p.get("name")
                )

        ProcessLog.objects.bulk_create(created_objs, ignore_conflicts=True)

        # Trigger alerts for IOC matches
        for ioc in ioc_matches:
            Alert.objects.create(
                title=f"IOC Match Triggered: {ioc.get('matched_process')}",
                severity=ioc.get("severity", "CRITICAL"),
                hostname=hostname,
                username="SYSTEM",
                description=f"IOC {ioc.get('ioc_type')} match '{ioc.get('ioc_value')}': {ioc.get('description')}",
                mitre_technique=ioc.get("mitre_technique", "T1071"),
                recommendation="Isolate endpoint and execute full incident response remediation.",
                source_module="IOCEngine",
                pid=ioc.get("pid"),
                process_name=ioc.get("matched_process")
            )

        return Response({"status": "success", "count": len(created_objs)}, status=status.HTTP_201_CREATED)

def processes_web_view(request):
    return render(request, "processes.html")
