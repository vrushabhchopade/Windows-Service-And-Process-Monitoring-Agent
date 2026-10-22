from django.db import models

class IOCRule(models.Model):
    IOC_TYPES = [
        ('FileName', 'File Name'),
        ('SHA256', 'SHA256 Hash'),
        ('MD5', 'MD5 Hash'),
        ('ProcessName', 'Process Name'),
        ('CommandLine', 'Command Line'),
        ('Registry', 'Registry Key'),
        ('IP', 'IP Address'),
        ('Domain', 'Domain Name'),
        ('URL', 'URL'),
    ]
    SEVERITIES = [
        ('CRITICAL', 'Critical'),
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
        ('LOW', 'Low'),
    ]

    ioc_type = models.CharField(max_length=50, choices=IOC_TYPES, db_index=True)
    value = models.CharField(max_length=500, db_index=True)
    description = models.TextField(blank=True, default='')
    severity = models.CharField(max_length=20, choices=SEVERITIES, default='HIGH')
    is_enabled = models.BooleanField(default=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"[{self.ioc_type}] {self.value} ({self.severity})"
