from django.urls import path
from apps.authentication.views import JWTLoginView, login_web_view, logout_web_view

urlpatterns = [
    path('api/v1/auth/login/', JWTLoginView.as_view(), name='api_login'),
    path('login/', login_web_view, name='login_web'),
    path('logout/', logout_web_view, name='logout_web'),
]
