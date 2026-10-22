from rest_framework import serializers
from apps.eventlogs.models import WindowsEventLog

class WindowsEventLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = WindowsEventLog
        fields = '__all__'
