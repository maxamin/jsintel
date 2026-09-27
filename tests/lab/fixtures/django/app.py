"""Minimal but real vulnerable Django app (modern Django, py3.14) for lab testing:
DEBUG=True (technical-500 pages), a login form with csrfmiddlewaretoken (Django
fingerprint), IDOR-style endpoints, and an exposed admin path."""
import os, sys
from django.conf import settings
BASE = os.path.dirname(os.path.abspath(__file__))
if not settings.configured:
    settings.configure(
        DEBUG=True, SECRET_KEY="lab-insecure-key", ALLOWED_HOSTS=["*"],
        ROOT_URLCONF=__name__,
        MIDDLEWARE=["django.middleware.common.CommonMiddleware",
                    "django.middleware.csrf.CsrfViewMiddleware"],
        DATABASES={}, INSTALLED_APPS=[],
        TEMPLATES=[{"BACKEND": "django.template.backends.django.DjangoTemplates",
                    "APP_DIRS": False, "OPTIONS": {}}],
    )
import django; django.setup()
from django.http import HttpResponse, JsonResponse
from django.urls import path
from django.middleware.csrf import get_token

def index(request):
    tok = get_token(request)
    return HttpResponse(f"""<!doctype html><html><head><title>DjangoLab</title>
<meta name="generator" content="Django"></head><body>
<a href="/api/v1/users">users</a> <a href="/admin/">admin</a>
<a href="/profile?id=1">profile</a> <a href="/download?file=report.pdf">dl</a>
<form action="/login" method="post">
  <input type="hidden" name="csrfmiddlewaretoken" value="{tok}">
  <input name="username"><input name="password" type="password"></form>
<!-- TODO remove debug endpoint /boom before prod --></body></html>""")

def users(request): return JsonResponse({"users": [{"id": 1, "name": "admin"}]})
def profile(request): return JsonResponse({"id": request.GET.get("id"), "ssn": "000-00-0000"})
def boom(request): raise RuntimeError("intentional error to expose the DEBUG traceback")

urlpatterns = [path("", index), path("api/v1/users", users), path("profile", profile), path("boom", boom)]

if __name__ == "__main__":
    from django.core.management import execute_from_command_line
    execute_from_command_line(["app.py", "runserver", sys.argv[1] if len(sys.argv) > 1 else "127.0.0.11:8092", "--noreload"])
