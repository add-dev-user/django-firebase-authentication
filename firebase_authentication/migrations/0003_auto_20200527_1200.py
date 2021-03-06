# Generated by Django 3.0.6 on 2020-05-27 10:48

from django.db import migrations
import phonenumber_field.modelfields


class Migration(migrations.Migration):

    dependencies = [
        ('firebase_authentication', '0002_auto_20200527_0846'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='phone_number',
            field=phonenumber_field.modelfields.PhoneNumberField(max_length=128, region=None, null=True, unique=True, verbose_name='Phone number'),
            preserve_default=False,
        ),
    ]
