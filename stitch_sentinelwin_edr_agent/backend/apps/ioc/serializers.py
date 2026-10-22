from rest_framework import serializers
from apps.ioc.models import IOCRule

class IOCRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = IOCRule
        fields = '__all__'
