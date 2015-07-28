# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('organizations', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Account',
            fields=[
            ],
            options={
                'proxy': True,
            },
            bases=('organizations.organization',),
        ),
        migrations.CreateModel(
            name='AccountUser',
            fields=[
            ],
            options={
                'proxy': True,
            },
            bases=('organizations.organizationuser',),
        ),
    ]
