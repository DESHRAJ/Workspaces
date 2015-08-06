from django.shortcuts import render, HttpResponse
from django.contrib.auth.decorators import login_required
import json
# Create your views here.

def current_user(request):
	if request.user.is_authenticated():
		return HttpResponse(json.dumps({"email":request.user.email}))
	else:
		return HttpResponse(json.dumps({"email":None}))

@login_required
def dashboard(request):
	request.session['hello'] = "world"
	return HttpResponse("Logged In")


