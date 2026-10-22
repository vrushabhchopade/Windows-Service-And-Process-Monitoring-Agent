from django.urls import path
from apps.settings_app.views import AgentSettingsView, settings_web_view

urlpatterns = [
    path('api/v1/settings/', AgentSettingsView.as_view(), name='agent_settings_api'),
    path('settings/', settings_web_view, name='settings_web'),
]
