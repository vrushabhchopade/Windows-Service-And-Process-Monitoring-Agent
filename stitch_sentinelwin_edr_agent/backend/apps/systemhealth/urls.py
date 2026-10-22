from django.urls import path, include
from rest_framework.routers import DefaultRouter
from apps.systemhealth.views import SystemHealthLogViewSet, SystemHealthTelemetryIngestView

router = DefaultRouter()
router.register(r'systemhealth', SystemHealthLogViewSet, basename='systemhealthlog')

urlpatterns = [
    path('api/v1/', include(router.urls)),
    path('api/v1/telemetry/systemhealth/', SystemHealthTelemetryIngestView.as_view(), name='telemetry_systemhealth'),
]
