from rest_framework import serializers
from apps.settings_app.models import AgentSettings

class AgentSettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = AgentSettings
        fields = '__all__'
