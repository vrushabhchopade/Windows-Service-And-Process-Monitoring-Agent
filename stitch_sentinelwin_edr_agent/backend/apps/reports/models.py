from django.db import models

class GeneratedReport(models.Model):
    title = models.CharField(max_length=255)
    report_type = models.CharField(max_length=50, default='Executive Summary')
    format = models.CharField(max_length=10, choices=[('PDF', 'PDF'), ('CSV', 'CSV'), ('JSON', 'JSON')])
    generated_by = models.CharField(max_length=255, default='SOC Analyst')
    file_path = models.CharField(max_length=500, blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.title} ({self.format}) - {self.created_at}"
