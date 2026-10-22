from django.shortcuts import render
from rest_framework import viewsets, permissions
from apps.alerts.models import Alert
from apps.alerts.serializers import AlertSerializer

class AlertViewSet(viewsets.ModelViewSet):
    queryset = Alert.objects.all()
    serializer_class = AlertSerializer
    permission_classes = [permissions.AllowAny]

    def get_queryset(self):
        qs = super().get_queryset()
        severity = self.request.query_params.get("severity")
        status_param = self.request.query_params.get("status")
        hostname = self.request.query_params.get("hostname")
        search = self.request.query_params.get("search")

        if severity:
            qs = qs.filter(severity__iexact=severity)
        if status_param:
            qs = qs.filter(status__iexact=status_param)
        if hostname:
            qs = qs.filter(hostname=hostname)
        if search:
            qs = qs.filter(title__icontains=search) | qs.filter(description__icontains=search)
        return qs

def alerts_web_view(request):
    return render(request, "alerts.html")
