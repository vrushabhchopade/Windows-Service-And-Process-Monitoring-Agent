from rest_framework import serializers
from apps.investigation.models import InvestigationCase

class InvestigationCaseSerializer(serializers.ModelSerializer):
    class Meta:
        model = InvestigationCase
        fields = '__all__'
