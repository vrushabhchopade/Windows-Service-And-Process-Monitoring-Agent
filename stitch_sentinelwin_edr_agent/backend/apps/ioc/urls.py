from django.urls import path, include
from rest_framework.routers import DefaultRouter
from apps.ioc.views import IOCRuleViewSet, IOCCSVImportView, ioc_web_view

router = DefaultRouter()
router.register(r'ioc', IOCRuleViewSet, basename='iocrule')

urlpatterns = [
    path('api/v1/ioc/import-csv/', IOCCSVImportView.as_view(), name='ioc_import_csv'),
    path('api/v1/', include(router.urls)),
    path('ioc/', ioc_web_view, name='ioc_web'),
]
