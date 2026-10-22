from django.db import models

class ProcessLog(models.Model):
    pid = models.IntegerField(db_index=True)
    ppid = models.IntegerField(db_index=True)
    name = models.CharField(max_length=255, db_index=True)
    parent_name = models.CharField(max_length=255, blank=True, default='')
    username = models.CharField(max_length=255, blank=True, default='')
    exe_path = models.TextField(blank=True, default='')
    cmdline = models.TextField(blank=True, default='')
    create_time = models.DateTimeField(blank=True, null=True)
    cpu_percent = models.FloatField(default=0.0)
    memory_percent = models.FloatField(default=0.0)
    md5 = models.CharField(max_length=32, blank=True, default='')
    sha256 = models.CharField(max_length=64, blank=True, default='')
    is_in_temp = models.BooleanField(default=False)
    is_signed = models.BooleanField(default=True)
    status = models.CharField(max_length=50, default='Running')
    hostname = models.CharField(max_length=255, db_index=True, default='WIN-EDR-AGENT-01')
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"[{self.hostname}] {self.name} (PID: {self.pid})"

class Endpoint(models.Model):
    agent_id = models.CharField(max_length=255, unique=True, db_index=True)
    enrollment_token = models.CharField(max_length=128, blank=True, default="")
    hostname = models.CharField(max_length=255, db_index=True)
    username = models.CharField(max_length=255, blank=True, default='')
    os_name = models.CharField(max_length=255, blank=True, default='')
    agent_version = models.CharField(max_length=50, default='2.0.0')
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    is_online = models.BooleanField(default=False)
    last_seen = models.DateTimeField(blank=True, null=True)
    registered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['hostname']

    def __str__(self):
        return f"{self.hostname} ({self.agent_id})"
