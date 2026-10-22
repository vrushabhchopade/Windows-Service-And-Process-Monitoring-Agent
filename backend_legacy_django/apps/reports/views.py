from django.shortcuts import render
from django.http import HttpResponse
from rest_framework import viewsets, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response

from apps.reports.models import GeneratedReport
from apps.reports.serializers import GeneratedReportSerializer
from apps.reports.report_generator import generate_pdf_report, generate_csv_report, generate_json_report

class GeneratedReportViewSet(viewsets.ModelViewSet):
    queryset = GeneratedReport.objects.all()
    serializer_class = GeneratedReportSerializer
    permission_classes = [permissions.AllowAny]

class ReportDownloadView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        fmt = request.query_params.get("format", "pdf").lower()
        title = request.query_params.get("title", "Stitch Sentinel EDR Security Report")

        # Record in database
        GeneratedReport.objects.create(
            title=title,
            report_type="Executive Audit Report",
            format=fmt.upper(),
            generated_by=request.user.username if request.user.is_authenticated else "SOC Analyst"
        )

        if fmt == "pdf":
            pdf_bytes = generate_pdf_report(title)
            response = HttpResponse(pdf_bytes, content_type='application/pdf')
            response['Content-Disposition'] = 'attachment; filename="Stitch_Sentinel_Report.pdf"'
            return response
        elif fmt == "csv":
            csv_str = generate_csv_report()
            response = HttpResponse(csv_str, content_type='text/csv')
            response['Content-Disposition'] = 'attachment; filename="Stitch_Sentinel_Alerts.csv"'
            return response
        elif fmt == "json":
            json_str = generate_json_report()
            response = HttpResponse(json_str, content_type='application/json')
            response['Content-Disposition'] = 'attachment; filename="Stitch_Sentinel_Report.json"'
            return response
        else:
            return Response({"error": "Unsupported format. Options: pdf, csv, json"}, status=status.HTTP_400_BAD_REQUEST)

def reports_web_view(request):
    return render(request, "reports.html")
