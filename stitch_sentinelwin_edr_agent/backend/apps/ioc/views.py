import csv
import io
from django.shortcuts import render
from rest_framework import viewsets, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from apps.ioc.models import IOCRule
from apps.ioc.serializers import IOCRuleSerializer

class IOCRuleViewSet(viewsets.ModelViewSet):
    queryset = IOCRule.objects.all()
    serializer_class = IOCRuleSerializer
    permission_classes = [permissions.AllowAny]

    def get_queryset(self):
        qs = super().get_queryset()
        ioc_type = self.request.query_params.get("ioc_type")
        enabled = self.request.query_params.get("enabled")
        search = self.request.query_params.get("search")

        if ioc_type:
            qs = qs.filter(ioc_type__iexact=ioc_type)
        if enabled == "true":
            qs = qs.filter(is_enabled=True)
        elif enabled == "false":
            qs = qs.filter(is_enabled=False)
        if search:
            qs = qs.filter(value__icontains=search) | qs.filter(description__icontains=search)
        return qs

class IOCCSVImportView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        if 'file' not in request.FILES:
            return Response({"error": "CSV file required in 'file' form field"}, status=status.HTTP_400_BAD_REQUEST)

        csv_file = request.FILES['file']
        try:
            decoded_file = csv_file.read().decode('utf-8')
            io_string = io.StringIO(decoded_file)
            reader = csv.DictReader(io_string)

            created_count = 0
            for row in reader:
                ioc_type = row.get('ioc_type') or row.get('type')
                value = row.get('value') or row.get('ioc')
                description = row.get('description', 'Imported via CSV')
                severity = row.get('severity', 'HIGH').upper()

                if ioc_type and value:
                    IOCRule.objects.get_or_create(
                        ioc_type=ioc_type,
                        value=value,
                        defaults={
                            'description': description,
                            'severity': severity if severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] else 'HIGH',
                            'is_enabled': True
                        }
                    )
                    created_count += 1

            return Response({"status": "success", "imported": created_count}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({"error": f"Failed to parse CSV file: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

def ioc_web_view(request):
    return render(request, "ioc_management.html")
