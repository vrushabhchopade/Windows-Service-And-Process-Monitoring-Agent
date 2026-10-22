from rest_framework import viewsets, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from apps.systemhealth.models import SystemHealthLog
from apps.systemhealth.serializers import SystemHealthLogSerializer
from apps.alerts.models import Alert

class SystemHealthLogViewSet(viewsets.ModelViewSet):
    queryset = SystemHealthLog.objects.all()
    serializer_class = SystemHealthLogSerializer
    permission_classes = [permissions.AllowAny]

class SystemHealthTelemetryIngestView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        hostname = request.data.get("hostname", "WIN-EDR-AGENT-01")
        cpu_p = request.data.get("cpu_percent", 0.0)
        ram_p = request.data.get("ram_percent", 0.0)
        disk_p = request.data.get("disk_percent", 0.0)

        obj = SystemHealthLog.objects.create(
            hostname=hostname,
            cpu_percent=cpu_p,
            ram_percent=ram_p,
            disk_percent=disk_p,
            disk_free_gb=request.data.get("disk_free_gb", 0.0),
            network_sent_mb=request.data.get("network_sent_mb", 0.0),
            network_recv_mb=request.data.get("network_recv_mb", 0.0),
            top_cpu_processes=request.data.get("top_cpu_processes", []),
            top_ram_processes=request.data.get("top_ram_processes", [])
        )

        # Generate alert if hardware threshold is exceeded
        if cpu_p > 85.0:
            Alert.objects.create(
                title=f"System Resource Exhaustion: High CPU Usage ({cpu_p}%)",
                severity="MEDIUM" if cpu_p < 95.0 else "HIGH",
                hostname=hostname,
                username="SYSTEM",
                description=f"CPU utilization spiked to {cpu_p}%. Top process: {request.data.get('top_cpu_processes', [{}])[0].get('name', 'N/A')}",
                mitre_technique="T1496 - Resource Hijacking",
                recommendation="Inspect top CPU consuming processes for unauthorized crypto-mining or denial-of-service activity.",
                source_module="CPUMonitor"
            )

        if ram_p > 90.0:
            Alert.objects.create(
                title=f"System Memory Warning: High RAM Usage ({ram_p}%)",
                severity="MEDIUM",
                hostname=hostname,
                username="SYSTEM",
                description=f"Memory utilization reached {ram_p}%.",
                mitre_technique="T1499 - Endpoint Denial of Service",
                recommendation="Audit memory consumption of active system processes.",
                source_module="MemoryMonitor"
            )

        return Response({"status": "success", "id": obj.id}, status=status.HTTP_201_CREATED)
