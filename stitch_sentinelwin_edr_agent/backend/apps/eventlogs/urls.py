from django.urls import path, include
from rest_framework.routers import DefaultRouter
from apps.eventlogs.views import WindowsEventLogViewSet, EventLogTelemetryIngestView, eventlogs_web_view

router = DefaultRouter()
router.register(r'eventlogs', WindowsEventLogViewSet, basename='windowseventlog')

urlpatterns = [
    path('api/v1/', include(router.urls)),
    path('api/v1/telemetry/eventlog/', EventLogTelemetryIngestView.as_view(), name='telemetry_eventlog'),
    path('event-logs/', eventlogs_web_view, name='eventlogs_web'),
]
