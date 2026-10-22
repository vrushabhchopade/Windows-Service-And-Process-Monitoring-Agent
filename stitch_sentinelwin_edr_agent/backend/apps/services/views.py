from django.shortcuts import render
from rest_framework import viewsets, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from apps.services.models import ServiceLog
from apps.services.serializers import ServiceLogSerializer
from apps.alerts.models import Alert

class ServiceLogViewSet(viewsets.ModelViewSet):
    queryset = ServiceLog.objects.all()
    serializer_class = ServiceLogSerializer
    permission_classes = [permissions.AllowAny]

    def get_queryset(self):
        qs = super().get_queryset()
        suspicious = self.request.query_params.get("suspicious")
        search = self.request.query_params.get("search")
        if suspicious == "true":
            qs = qs.filter(is_suspicious=True)
        if search:
            qs = qs.filter(service_name__icontains=search) | qs.filter(display_name__icontains=search)
        return qs

class ServiceTelemetryIngestView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        hostname = request.data.get("hostname", "WIN-EDR-AGENT-01")
        services_data = request.data.get("services", [])

        created_objs = []
        for s in services_data:
            obj = ServiceLog(
                service_name=s.get("service_name"),
                display_name=s.get("display_name"),
                binary_path=s.get("binary_path", ""),
                startup_type=s.get("startup_type", "Automatic"),
                status=s.get("status", "Running"),
                service_account=s.get("service_account", "LocalSystem"),
                description=s.get("description", ""),
                is_suspicious=s.get("is_suspicious", False),
                hostname=hostname
            )
            created_objs.append(obj)

            # Generate alerts for suspicious services
            warnings = s.get("warnings", [])
            for w in warnings:
                Alert.objects.create(
                    title=f"Suspicious Service: {s.get('service_name')}",
                    severity="HIGH" if "CRITICAL" not in w else "CRITICAL",
                    hostname=hostname,
                    username=s.get("service_account", "LocalSystem"),
                    description=w,
                    mitre_technique="T1543.003 - Create or Modify System Process: Windows Service",
                    recommendation=f"Audit binary path '{s.get('binary_path')}' and verify service startup configuration.",
                    source_module="ServiceMonitor"
                )

        ServiceLog.objects.bulk_create(created_objs, ignore_conflicts=True)
        return Response({"status": "success", "count": len(created_objs)}, status=status.HTTP_201_CREATED)

def services_web_view(request):
    return render(request, "services.html")
