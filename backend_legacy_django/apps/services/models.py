from django.db import models

class ServiceLog(models.Model):
    service_name = models.CharField(max_length=255, db_index=True)
    display_name = models.CharField(max_length=255)
    binary_path = models.TextField(blank=True, default='')
    startup_type = models.CharField(max_length=50, default='Automatic')
    status = models.CharField(max_length=50, default='Running')
    service_account = models.CharField(max_length=255, default='LocalSystem')
    description = models.TextField(blank=True, default='')
    is_suspicious = models.BooleanField(default=False)
    hostname = models.CharField(max_length=255, db_index=True, default='WIN-EDR-AGENT-01')
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"[{self.hostname}] Service: {self.service_name} ({self.status})"
