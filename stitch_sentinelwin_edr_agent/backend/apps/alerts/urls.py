from django.urls import path, include
from rest_framework.routers import DefaultRouter
from apps.alerts.views import AlertViewSet, alerts_web_view

router = DefaultRouter()
router.register(r'alerts', AlertViewSet, basename='alert')

urlpatterns = [
    path('api/v1/', include(router.urls)),
    path('alerts/', alerts_web_view, name='alerts_web'),
]
