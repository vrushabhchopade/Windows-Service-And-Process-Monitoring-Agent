from django.shortcuts import render
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from rest_framework import viewsets, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response

from apps.processes.models import ProcessLog, Endpoint
from apps.processes.serializers import ProcessLogSerializer
from apps.alerts.models import Alert


class ProcessLogViewSet(viewsets.ModelViewSet):
    queryset = ProcessLog.objects.all().order_by('-timestamp', '-id')
    serializer_class = ProcessLogSerializer
    permission_classes = [permissions.AllowAny]

    def get_queryset(self):
        qs = super().get_queryset()

        hostname = self.request.query_params.get("hostname")
        search = self.request.query_params.get("search")

        if hostname:
            qs = qs.filter(hostname=hostname)

        if search:
            qs = qs.filter(
                name__icontains=search
            ) | qs.filter(
                cmdline__icontains=search
            )

        return qs


# ============================================================
# ENDPOINT REGISTER
# ============================================================

class EndpointRegisterView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        agent_id = request.data.get("agent_id")
        hostname = request.data.get("hostname")
        enrollment_token = request.data.get("enrollment_token")

        if not enrollment_token:
            return Response(
                {
                    "status": "error",
                    "message": "enrollment_token is required"
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        if not agent_id or not hostname:
            return Response(
                {
                    "status": "error",
                    "message": "agent_id and hostname are required"
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        # ----------------------------------------------------
        # VERIFY EXISTING ENDPOINT ENROLLMENT TOKEN
        # ----------------------------------------------------

        try:
            existing_endpoint = Endpoint.objects.get(
                agent_id=agent_id
            )
        except Endpoint.DoesNotExist:
            return Response(
                {
                    "status": "error",
                    "message": "Endpoint is not enrolled"
                },
                status=status.HTTP_403_FORBIDDEN
            )

        if existing_endpoint.enrollment_token != enrollment_token:
            return Response(
                {
                    "status": "error",
                    "message": "Invalid enrollment token"
                },
                status=status.HTTP_403_FORBIDDEN
            )

        # ----------------------------------------------------
        # UPDATE ENDPOINT
        # ----------------------------------------------------

        endpoint, created = Endpoint.objects.update_or_create(
            agent_id=agent_id,
            defaults={
                "hostname": hostname,
                "username": request.data.get("username", ""),
                "os_name": request.data.get("os_name", ""),
                "agent_version": request.data.get(
                    "agent_version",
                    "2.0.0"
                ),
                "ip_address": request.data.get("ip_address"),
                "is_online": True,
                "last_seen": timezone.now(),
            }
        )

        return Response(
            {
                "status": "success",
                "registered": created,
                "endpoint_id": endpoint.id,
                "agent_id": endpoint.agent_id,
                "hostname": endpoint.hostname,
                "is_online": endpoint.is_online,
                "last_seen": endpoint.last_seen,
            },
            status=status.HTTP_200_OK
        )


# ============================================================
# ENDPOINT HEARTBEAT
# ============================================================

class EndpointHeartbeatView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        agent_id = request.data.get("agent_id")

        if not agent_id:
            return Response(
                {
                    "status": "error",
                    "message": "agent_id is required"
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            endpoint = Endpoint.objects.get(
                agent_id=agent_id
            )
        except Endpoint.DoesNotExist:
            return Response(
                {
                    "status": "error",
                    "message": "Endpoint not found"
                },
                status=status.HTTP_404_NOT_FOUND
            )

        endpoint.is_online = True
        endpoint.last_seen = timezone.now()

        endpoint.save(
            update_fields=[
                "is_online",
                "last_seen"
            ]
        )

        return Response(
            {
                "status": "success",
                "agent_id": endpoint.agent_id,
                "hostname": endpoint.hostname,
                "is_online": endpoint.is_online,
                "last_seen": endpoint.last_seen,
            },
            status=status.HTTP_200_OK
        )


# ============================================================
# PROCESS TELEMETRY INGEST
# ============================================================

class ProcessTelemetryIngestView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        hostname = request.data.get(
            "hostname",
            "WIN-EDR-AGENT-01"
        )

        processes_data = request.data.get(
            "processes",
            []
        )

        ioc_matches = request.data.get(
            "ioc_matches",
            []
        )

        created_objs = []

        for p in processes_data:

            # ------------------------------------------------
            # SAFE PROCESS CREATE TIME
            # ------------------------------------------------

            raw_create_time = p.get("create_time")
            create_time = None

            if isinstance(raw_create_time, str):
                try:
                    create_time = parse_datetime(
                        raw_create_time
                    )
                except (TypeError, ValueError):
                    create_time = None

            # ------------------------------------------------
            # PROCESS OBJECT
            # ------------------------------------------------

            obj = ProcessLog(
                pid=p.get("pid"),
                ppid=p.get("ppid"),
                name=p.get(
                    "name",
                    "unknown"
                ),
                parent_name=p.get(
                    "parent_name",
                    "N/A"
                ),
                username=p.get(
                    "username",
                    "SYSTEM"
                ),
                exe_path=p.get(
                    "exe_path",
                    ""
                ),
                cmdline=p.get(
                    "cmdline",
                    ""
                ),
                create_time=create_time,
                cpu_percent=p.get(
                    "cpu_percent",
                    0.0
                ),
                memory_percent=p.get(
                    "memory_percent",
                    0.0
                ),
                md5=p.get(
                    "md5",
                    ""
                ),
                sha256=p.get(
                    "sha256",
                    ""
                ),
                is_in_temp=bool(
                    p.get("is_in_temp") or False
                ),
                is_signed=bool(
                    p.get("is_signed")
                    if p.get("is_signed") is not None
                    else True
                ),
                status=p.get(
                    "status",
                    "Running"
                ),
                hostname=hostname
            )

            created_objs.append(obj)

            # ------------------------------------------------
            # SUSPICIOUS PROCESS ALERTS
            # ------------------------------------------------

            flags = p.get(
                "suspicious_flags",
                []
            )

            if not isinstance(flags, list):
                flags = []

            for flag in flags:

                if not isinstance(flag, dict):
                    continue

                Alert.objects.create(
                    title=(
                        f"Suspicious Process: "
                        f"{p.get('name')}"
                    ),
                    severity=flag.get(
                        "severity",
                        "HIGH"
                    ),
                    hostname=hostname,
                    username=p.get(
                        "username",
                        "SYSTEM"
                    ),
                    description=flag.get(
                        "description",
                        ""
                    ),
                    mitre_technique=flag.get(
                        "mitre",
                        "T1059"
                    ),
                    recommendation=(
                        f"Terminate process PID "
                        f"{p.get('pid')} and quarantine "
                        f"executable "
                        f"{p.get('exe_path')}"
                    ),
                    source_module="ProcessMonitor",
                    pid=p.get("pid"),
                    process_name=p.get("name")
                )

        # ====================================================
        # SAVE PROCESS TELEMETRY
        # ====================================================

        print(
            "PROCESS TELEMETRY:",
            len(processes_data),
            "CREATED OBJECTS:",
            len(created_objs)
        )

        if created_objs:
            ProcessLog.objects.bulk_create(
                created_objs
            )

        # ====================================================
        # IOC MATCH ALERTS
        # ====================================================

        if not isinstance(ioc_matches, list):
            ioc_matches = []

        for ioc in ioc_matches:

            if not isinstance(ioc, dict):
                continue

            Alert.objects.create(
                title=(
                    f"IOC Match Triggered: "
                    f"{ioc.get('matched_process')}"
                ),
                severity=ioc.get(
                    "severity",
                    "CRITICAL"
                ),
                hostname=hostname,
                username="SYSTEM",
                description=(
                    f"IOC {ioc.get('ioc_type')} "
                    f"match '{ioc.get('ioc_value')}': "
                    f"{ioc.get('description')}"
                ),
                mitre_technique=ioc.get(
                    "mitre_technique",
                    "T1071"
                ),
                recommendation=(
                    "Isolate endpoint and execute "
                    "full incident response remediation."
                ),
                source_module="IOCEngine",
                pid=ioc.get("pid"),
                process_name=ioc.get(
                    "matched_process"
                )
            )

        return Response(
            {
                "status": "success",
                "count": len(created_objs)
            },
            status=status.HTTP_201_CREATED
        )


# ============================================================
# PROCESSES WEB VIEW
# ============================================================

def processes_web_view(request):
    return render(
        request,
        "processes.html"
    )


# ============================================================
# ENDPOINT LIST
# ============================================================

class EndpointListView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request):

        endpoints = Endpoint.objects.all()

        data = []

        for endpoint in endpoints:

            data.append(
                {
                    "id": endpoint.id,
                    "agent_id": endpoint.agent_id,
                    "hostname": endpoint.hostname,
                    "username": endpoint.username,
                    "os_name": endpoint.os_name,
                    "ip_address": endpoint.ip_address,
                    "is_online": endpoint.is_online,
                    "last_seen": endpoint.last_seen,
                    "agent_version": endpoint.agent_version,
                }
            )

        return Response(
            data,
            status=status.HTTP_200_OK
        )