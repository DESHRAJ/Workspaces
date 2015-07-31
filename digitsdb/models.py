from django.db import models
# Create your models here.
from django.contrib.auth.models import User
from organizations.models import Organization

class Job(models.Model):
	job_id = models.CharField(max_length = 100)
	workspace = models.ForeignKey(Organization)

