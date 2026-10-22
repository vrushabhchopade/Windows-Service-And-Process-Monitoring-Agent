from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from apps.core.views import dashboard_web_view

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # Root Dashboard View
    path('', dashboard_web_view, name='dashboard_web'),

    # Modular App URLs
    path('', include('apps.authentication.urls')),
    path('', include('apps.processes.urls')),
    path('', include('apps.services.urls')),
    path('', include('apps.eventlogs.urls')),
    path('', include('apps.systemhealth.urls')),
    path('', include('apps.alerts.urls')),
    path('', include('apps.ioc.urls')),
    path('', include('apps.investigation.urls')),
    path('', include('apps.reports.urls')),
    path('', include('apps.analytics.urls')),
    path('', include('apps.settings_app.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
