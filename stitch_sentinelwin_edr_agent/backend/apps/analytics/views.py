from django.shortcuts import render
from django.db.models import Count
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions

from apps.alerts.models import Alert
from apps.processes.models import ProcessLog
from apps.services.models import ServiceLog
from apps.eventlogs.models import WindowsEventLog
from apps.systemhealth.models import SystemHealthLog

class AnalyticsOverviewView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        total_alerts = Alert.objects.count()
        critical_alerts = Alert.objects.filter(severity='CRITICAL').count()
        high_alerts = Alert.objects.filter(severity='HIGH').count()
        medium_alerts = Alert.objects.filter(severity='MEDIUM').count()
        low_alerts = Alert.objects.filter(severity='LOW').count()

        # Severity breakdown
        severity_counts = {
            "CRITICAL": critical_alerts,
            "HIGH": high_alerts,
            "MEDIUM": medium_alerts,
            "LOW": low_alerts
        }

        # Top MITRE Techniques
        mitre_counts = list(
            Alert.objects.values('mitre_technique')
            .annotate(count=Count('id'))
            .order_by('-count')[:8]
        )

        # Event ID distribution
        event_id_counts = list(
            WindowsEventLog.objects.values('event_id')
            .annotate(count=Count('id'))
            .order_by('-count')[:8]
        )

        # Latest System Health
        latest_health = SystemHealthLog.objects.first()
        health_data = {
            "cpu_percent": latest_health.cpu_percent if latest_health else 15.0,
            "ram_percent": latest_health.ram_percent if latest_health else 42.0,
            "disk_percent": latest_health.disk_percent if latest_health else 35.0,
            "network_sent_mb": latest_health.network_sent_mb if latest_health else 12.4,
            "network_recv_mb": latest_health.network_recv_mb if latest_health else 84.1
        }

        total_procs = ProcessLog.objects.values('pid').distinct().count()
        suspicious_services = ServiceLog.objects.filter(is_suspicious=True).count()

        return Response({
            "total_alerts": total_alerts,
            "total_processes": total_procs,
            "suspicious_services": suspicious_services,
            "severity_counts": severity_counts,
            "mitre_counts": mitre_counts,
            "event_id_counts": event_id_counts,
            "health": health_data
        })

def analytics_web_view(request):
    return render(request, "analytics.html")
