from django.db import models

class AgentSettings(models.Model):
    monitoring_interval_seconds = models.IntegerField(default=10)
    enable_process_monitor = models.BooleanField(default=True)
    enable_service_monitor = models.BooleanField(default=True)
    enable_eventlog_monitor = models.BooleanField(default=True)
    cpu_threshold_percent = models.FloatField(default=85.0)
    memory_threshold_percent = models.FloatField(default=90.0)
    retention_days = models.IntegerField(default=30)
    email_webhook = models.CharField(max_length=500, blank=True, default='')
    telegram_webhook = models.CharField(max_length=500, blank=True, default='')
    slack_webhook = models.CharField(max_length=500, blank=True, default='')
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Agent Configuration (Updated: {self.updated_at.strftime('%Y-%m-%d %H:%M')})"
