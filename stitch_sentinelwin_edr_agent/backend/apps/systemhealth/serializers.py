from rest_framework import serializers
from apps.systemhealth.models import SystemHealthLog

class SystemHealthLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = SystemHealthLog
        fields = '__all__'
