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

        # =====================================================
        # ALERTS
        # =====================================================

        total_alerts = Alert.objects.count()

        critical_alerts = Alert.objects.filter(
            severity="CRITICAL"
        ).count()

        high_alerts = Alert.objects.filter(
            severity="HIGH"
        ).count()

        medium_alerts = Alert.objects.filter(
            severity="MEDIUM"
        ).count()

        low_alerts = Alert.objects.filter(
            severity="LOW"
        ).count()

        severity_counts = {
            "CRITICAL": critical_alerts,
            "HIGH": high_alerts,
            "MEDIUM": medium_alerts,
            "LOW": low_alerts
        }

        # =====================================================
        # MITRE TECHNIQUES
        # =====================================================

        mitre_counts = list(
            Alert.objects
            .values("mitre_technique")
            .annotate(count=Count("id"))
            .order_by("-count")[:8]
        )

        # =====================================================
        # EVENT ID DISTRIBUTION
        # =====================================================

        event_id_counts = list(
            WindowsEventLog.objects
            .values("event_id")
            .annotate(count=Count("id"))
            .order_by("-count")[:8]
        )

        # =====================================================
        # LATEST SYSTEM HEALTH
        # =====================================================

        latest_health = (
            SystemHealthLog.objects
            .order_by("-timestamp")
            .first()
        )

        if latest_health:

            health_data = {
                "cpu_percent": float(
                    latest_health.cpu_percent
                ),

                "ram_percent": float(
                    latest_health.ram_percent
                ),

                "disk_percent": float(
                    latest_health.disk_percent
                ),

                "network_sent_mb": float(
                    latest_health.network_sent_mb
                ),

                "network_recv_mb": float(
                    latest_health.network_recv_mb
                )
            }

        else:

            health_data = {
                "cpu_percent": 0.0,
                "ram_percent": 0.0,
                "disk_percent": 0.0,
                "network_sent_mb": 0.0,
                "network_recv_mb": 0.0
            }

        # =====================================================
        # LIVE PROCESS COUNT
        # =====================================================

        latest_process = (
            ProcessLog.objects
            .order_by("-timestamp")
            .first()
        )

        if latest_process:

            latest_process_timestamp = latest_process.timestamp

            total_procs = (
                ProcessLog.objects
                .filter(
                    hostname=latest_process.hostname,
                    timestamp=latest_process_timestamp,
                    status="Running"
                )
                .count()
            )

        else:

            total_procs = 0

        # =====================================================
        # LIVE SUSPICIOUS SERVICES
        # =====================================================

        latest_service = (
            ServiceLog.objects
            .order_by("-timestamp")
            .first()
        )

        if latest_service:

            latest_service_timestamp = latest_service.timestamp

            suspicious_services = (
                ServiceLog.objects
                .filter(
                    hostname=latest_service.hostname,
                    timestamp=latest_service_timestamp,
                    is_suspicious=True
                )
                .count()
            )

        else:

            suspicious_services = 0

        # =====================================================
        # RESPONSE
        # =====================================================

        return Response({

            "total_alerts":
                total_alerts,

            "total_processes":
                total_procs,

            "suspicious_services":
                suspicious_services,

            "severity_counts":
                severity_counts,

            "mitre_counts":
                mitre_counts,

            "event_id_counts":
                event_id_counts,

            "health":
                health_data
        })


def analytics_web_view(request):

    return render(
        request,
        "analytics.html"
    )