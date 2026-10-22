from django.urls import path, include
from rest_framework.routers import DefaultRouter
from apps.reports.views import GeneratedReportViewSet, ReportDownloadView, reports_web_view

router = DefaultRouter()
router.register(r'reports', GeneratedReportViewSet, basename='generatedreport')

urlpatterns = [
    path('api/v1/', include(router.urls)),
    path('api/v1/reports/download/', ReportDownloadView.as_view(), name='report_download'),
    path('reports/', reports_web_view, name='reports_web'),
]
