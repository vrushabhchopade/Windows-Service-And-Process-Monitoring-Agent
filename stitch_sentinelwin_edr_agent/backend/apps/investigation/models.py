from django.db import models

class InvestigationCase(models.Model):
    STATUS_CHOICES = [
        ('Open', 'Open'),
        ('Under Investigation', 'Under Investigation'),
        ('Closed', 'Closed'),
    ]

    title = models.CharField(max_length=255)
    hostname = models.CharField(max_length=255, db_index=True)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='Open')
    assigned_analyst = models.CharField(max_length=255, default='SOC Analyst')
    notes = models.TextField(blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Case #{self.id}: {self.title} ({self.hostname})"
