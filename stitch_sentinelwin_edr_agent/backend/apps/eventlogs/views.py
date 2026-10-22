from django.shortcuts import render
from rest_framework import viewsets, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from apps.eventlogs.models import WindowsEventLog
from apps.eventlogs.serializers import WindowsEventLogSerializer
from apps.alerts.models import Alert

class WindowsEventLogViewSet(viewsets.ModelViewSet):
    queryset = WindowsEventLog.objects.all()
    serializer_class = WindowsEventLogSerializer
    permission_classes = [permissions.AllowAny]

    def get_queryset(self):
        qs = super().get_queryset()
        event_id = self.request.query_params.get("event_id")
        channel = self.request.query_params.get("channel")
        severity = self.request.query_params.get("severity")
        if event_id:
            qs = qs.filter(event_id=event_id)
        if channel:
            qs = qs.filter(log_channel__iexact=channel)
        if severity:
            qs = qs.filter(severity__iexact=severity)
        return qs

class EventLogTelemetryIngestView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        hostname = request.data.get("hostname", "WIN-EDR-AGENT-01")
        logs_data = request.data.get("logs", [])

        created_objs = []
        for l in logs_data:
            sev = l.get("severity", "INFO")
            evt_id = l.get("event_id")
            mitre = l.get("mitre_technique", "N/A")
            msg = l.get("message", "")

            obj = WindowsEventLog(
                log_channel=l.get("log_channel", "Security"),
                event_id=evt_id,
                source=l.get("source", "System"),
                message=msg,
                computer=hostname,
                user=l.get("user", "SYSTEM"),
                severity=sev,
                mitre_technique=mitre
            )
            created_objs.append(obj)

            # Auto create Alert for High/Critical events (e.g. 1102 log clear, 7045 new service, Sysmon LSASS access)
            if sev in ["HIGH", "CRITICAL"]:
                Alert.objects.create(
                    title=f"Security Event ID {evt_id}: {l.get('source')}",
                    severity=sev,
                    hostname=hostname,
                    username=l.get("user", "SYSTEM"),
                    description=msg,
                    mitre_technique=mitre,
                    recommendation="Investigate security event origin and review computer audit policies.",
                    source_module="EventLogMonitor"
                )

        WindowsEventLog.objects.bulk_create(created_objs, ignore_conflicts=True)
        return Response({"status": "success", "count": len(created_objs)}, status=status.HTTP_201_CREATED)

def eventlogs_web_view(request):
    return render(request, "event_logs.html")
