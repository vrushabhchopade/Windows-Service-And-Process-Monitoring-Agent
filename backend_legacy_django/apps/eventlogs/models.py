from django.db import models

class WindowsEventLog(models.Model):
    log_channel = models.CharField(max_length=100, db_index=True)
    event_id = models.IntegerField(db_index=True)
    source = models.CharField(max_length=255)
    message = models.TextField()
    computer = models.CharField(max_length=255, db_index=True, default='WIN-EDR-AGENT-01')
    user = models.CharField(max_length=255, default='SYSTEM')
    severity = models.CharField(max_length=20, default='INFO', db_index=True)
    mitre_technique = models.CharField(max_length=255, blank=True, default='N/A')
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"[{self.computer}] Event {self.event_id} ({self.log_channel}): {self.severity}"
