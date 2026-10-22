from django.urls import path, include
from rest_framework.routers import DefaultRouter
from apps.investigation.views import InvestigationCaseViewSet, ProcessTreeDetailView, investigation_web_view

router = DefaultRouter()
router.register(r'cases', InvestigationCaseViewSet, basename='investigationcase')

urlpatterns = [
    path('api/v1/investigation/', include(router.urls)),
    path('api/v1/investigation/<str:hostname>/process-tree/', ProcessTreeDetailView.as_view(), name='process_tree_detail'),
    path('investigation/', investigation_web_view, name='investigation_web'),
]
