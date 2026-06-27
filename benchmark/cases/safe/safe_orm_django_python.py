# SAFE: Django ORM filter() binds parameters. Trap: the request value is passed to
# filter(), which looks like a raw lookup, but the ORM parameterises it.
from django.http import JsonResponse
from myapp.models import User
def search(request):
    email = request.GET.get("email", "")
    users = User.objects.filter(email=email).values("id", "name")
    return JsonResponse(list(users), safe=False)
