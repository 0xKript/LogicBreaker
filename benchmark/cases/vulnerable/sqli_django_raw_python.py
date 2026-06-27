# VULN: Django .raw() with %-formatted user input (no params list).
from django.http import JsonResponse
from myapp.models import Account
def balance(request):
    acct = request.GET.get("acct")
    rows = Account.objects.raw("SELECT * FROM accounts WHERE number = '%s'" % acct)
    return JsonResponse({"rows": [r.id for r in rows]})
