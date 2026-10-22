from django.db import models

class Alert(models.Model):
    SEVERITY_CHOICES = [
        ('CRITICAL', 'Critical'),
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
        ('LOW', 'Low'),
    ]
    STATUS_CHOICES = [
        ('New', 'New'),
        ('In Progress', 'In Progress'),
        ('Resolved', 'Resolved'),
    ]

    title = models.CharField(max_length=255)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='HIGH', db_index=True)
    hostname = models.CharField(max_length=255, db_index=True, default='WIN-EDR-AGENT-01')
    username = models.CharField(max_length=255, blank=True, default='SYSTEM')
    description = models.TextField()
    mitre_technique = models.CharField(max_length=255, blank=True, default='T1059')
    recommendation = models.TextField(blank=True, default='')
    source_module = models.CharField(max_length=100, default='RuleEngine')
    pid = models.IntegerField(null=True, blank=True)
    process_name = models.CharField(max_length=255, blank=True, default='')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='New', db_index=True)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"[{self.severity}] {self.title} - {self.hostname} ({self.status})"
