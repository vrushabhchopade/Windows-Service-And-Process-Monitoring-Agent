from django.contrib import admin
from apps.processes.models import ProcessLog, Endpoint


@admin.register(Endpoint)
class EndpointAdmin(admin.ModelAdmin):
    list_display = (
        "hostname",
        "agent_id",
        "username",
        "os_name",
        "ip_address",
        "is_online",
        "last_seen",
    )

    list_filter = (
        "is_online",
        "os_name",
    )

    search_fields = (
        "hostname",
        "agent_id",
        "username",
        "ip_address",
    )


@admin.register(ProcessLog)
class ProcessLogAdmin(admin.ModelAdmin):
    list_display = (
        "hostname",
        "name",
        "pid",
        "username",
        "status",
        "timestamp",
    )

    list_filter = (
        "hostname",
        "status",
    )

    search_fields = (
        "hostname",
        "name",
        "pid",
        "username",
    )