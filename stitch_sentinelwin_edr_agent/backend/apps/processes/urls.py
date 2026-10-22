from django.urls import path, include
from rest_framework.routers import DefaultRouter
from apps.processes.views import ProcessLogViewSet, ProcessTelemetryIngestView, processes_web_view

router = DefaultRouter()
router.register(r'processes', ProcessLogViewSet, basename='processlog')

urlpatterns = [
    path('api/v1/', include(router.urls)),
    path('api/v1/telemetry/process/', ProcessTelemetryIngestView.as_view(), name='telemetry_process'),
    path('processes/', processes_web_view, name='processes_web'),
]
