from django.db import models

class SystemHealthLog(models.Model):
    cpu_percent = models.FloatField(default=0.0)
    ram_percent = models.FloatField(default=0.0)
    disk_percent = models.FloatField(default=0.0)
    disk_free_gb = models.FloatField(default=0.0)
    network_sent_mb = models.FloatField(default=0.0)
    network_recv_mb = models.FloatField(default=0.0)
    top_cpu_processes = models.JSONField(default=list, blank=True)
    top_ram_processes = models.JSONField(default=list, blank=True)
    hostname = models.CharField(max_length=255, db_index=True, default='WIN-EDR-AGENT-01')
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"[{self.hostname}] CPU: {self.cpu_percent}% | RAM: {self.ram_percent}% | Disk: {self.disk_percent}%"
