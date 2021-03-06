# -*- coding: utf-8 -*-
# Generated by Django 1.11.3 on 2017-08-22 22:32
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('blog', '0002_auto_20170708_1039'),
    ]

    operations = [
        migrations.AddField(
            model_name='category',
            name='slug',
            field=models.SlugField(default='test', editable=False, unique=True),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='tag',
            name='slug',
            field=models.SlugField(default='test', editable=False, unique=True),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='post',
            name='slug',
            field=models.SlugField(editable=False, unique=True),
        ),
    ]
