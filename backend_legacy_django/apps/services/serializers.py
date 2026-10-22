from rest_framework import serializers
from apps.services.models import ServiceLog

class ServiceLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = ServiceLog
        fields = '__all__'
