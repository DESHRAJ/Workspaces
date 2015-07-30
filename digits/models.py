from django.db import models
# Create your models here.
from django.contrib.auth.models import User
from organizations.models import OrganizationUser

# class Account(Organization):
#     class Meta:
#         proxy = True

# class AccountUser(OrganizationUser):
#     class Meta:
#         proxy = True


class Jobs(models.Model):
	job_id = models.CharField(max_length = 10)
	workspace = models.ForeignKey(OrganizationUser)

