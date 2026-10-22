from django.urls import path, include
from rest_framework.routers import DefaultRouter

from apps.processes.views import (
    ProcessLogViewSet,
    ProcessTelemetryIngestView,
    EndpointRegisterView,
    EndpointHeartbeatView,
    EndpointListView,
    processes_web_view,
)


router = DefaultRouter()

router.register(
    r'processes',
    ProcessLogViewSet,
    basename='processlog'
)


urlpatterns = [

    # Process API
    path(
        'api/v1/',
        include(router.urls)
    ),

    # Process Telemetry
    path(
        'api/v1/telemetry/process/',
        ProcessTelemetryIngestView.as_view(),
        name='telemetry_process'
    ),

    # Endpoint Registration
    path(
        'api/v1/endpoints/register/',
        EndpointRegisterView.as_view(),
        name='endpoint_register'
    ),

    # Endpoint Heartbeat
    path(
        'api/v1/endpoints/heartbeat/',
        EndpointHeartbeatView.as_view(),
        name='endpoint_heartbeat'
    ),

    # Endpoint List
    path(
        'api/v1/endpoints/',
        EndpointListView.as_view(),
        name='endpoint_list'
    ),

    # Processes Web Page
    path(
        'processes/',
        processes_web_view,
        name='processes_web'
    ),
]
