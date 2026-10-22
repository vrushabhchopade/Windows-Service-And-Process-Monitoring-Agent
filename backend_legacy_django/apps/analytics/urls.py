from django.urls import path
from apps.analytics.views import AnalyticsOverviewView, analytics_web_view

urlpatterns = [
    path('api/v1/analytics/overview/', AnalyticsOverviewView.as_view(), name='analytics_overview'),
    path('analytics/', analytics_web_view, name='analytics_web'),
]
