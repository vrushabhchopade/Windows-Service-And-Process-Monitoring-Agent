from django.shortcuts import render

def dashboard_web_view(request):
    return render(request, "dashboard.html")
