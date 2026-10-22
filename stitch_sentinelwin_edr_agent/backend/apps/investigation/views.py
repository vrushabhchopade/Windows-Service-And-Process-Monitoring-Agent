from django.shortcuts import render
from rest_framework import viewsets, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from apps.investigation.models import InvestigationCase
from apps.investigation.serializers import InvestigationCaseSerializer
from apps.processes.models import ProcessLog
from apps.alerts.models import Alert
from apps.eventlogs.models import WindowsEventLog

class InvestigationCaseViewSet(viewsets.ModelViewSet):
    queryset = InvestigationCase.objects.all()
    serializer_class = InvestigationCaseSerializer
    permission_classes = [permissions.AllowAny]

class ProcessTreeDetailView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request, hostname):
        procs = ProcessLog.objects.filter(hostname=hostname).order_by('-timestamp')[:100]
        nodes = []
        pid_map = {}
        
        for p in procs:
            if p.pid not in pid_map:
                pid_map[p.pid] = True
                nodes.append({
                    "id": p.pid,
                    "pid": p.pid,
                    "ppid": p.ppid,
                    "name": p.name,
                    "parent_name": p.parent_name,
                    "exe_path": p.exe_path,
                    "cmdline": p.cmdline,
                    "username": p.username,
                    "cpu_percent": p.cpu_percent,
                    "memory_percent": p.memory_percent,
                    "is_in_temp": p.is_in_temp,
                    "is_signed": p.is_signed
                })
        
        alerts = Alert.objects.filter(hostname=hostname).order_by('-timestamp')[:20]
        events = WindowsEventLog.objects.filter(computer=hostname).order_by('-timestamp')[:20]

        return Response({
            "hostname": hostname,
            "processes": nodes,
            "alerts": [
                {"id": a.id, "title": a.title, "severity": a.severity, "description": a.description, "timestamp": a.timestamp.isoformat()}
                for a in alerts
            ],
            "events": [
                {"id": e.id, "event_id": e.event_id, "source": e.source, "message": e.message, "severity": e.severity, "timestamp": e.timestamp.isoformat()}
                for e in events
            ]
        })

def investigation_web_view(request):
    return render(request, "investigation.html")
