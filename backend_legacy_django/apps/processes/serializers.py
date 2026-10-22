from rest_framework import serializers
from apps.processes.models import ProcessLog

class ProcessLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProcessLog
        fields = '__all__'
