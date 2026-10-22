from django.shortcuts import render
from rest_framework import permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from apps.settings_app.models import AgentSettings
from apps.settings_app.serializers import AgentSettingsSerializer

class AgentSettingsView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        obj, _ = AgentSettings.objects.get_or_create(id=1)
        serializer = AgentSettingsSerializer(obj)
        return Response(serializer.data)

    def post(self, request):
        obj, _ = AgentSettings.objects.get_or_create(id=1)
        serializer = AgentSettingsSerializer(obj, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

def settings_web_view(request):
    return render(request, "settings.html")
