from django.urls import path, include
from rest_framework.routers import DefaultRouter
from apps.services.views import ServiceLogViewSet, ServiceTelemetryIngestView, services_web_view

router = DefaultRouter()
router.register(r'services', ServiceLogViewSet, basename='servicelog')

urlpatterns = [
    path('api/v1/', include(router.urls)),
    path('api/v1/telemetry/service/', ServiceTelemetryIngestView.as_view(), name='telemetry_service'),
    path('services/', services_web_view, name='services_web'),
]
