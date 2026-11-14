# Near-misses without a Django import go above the framework imports:
# the import must precede the use for a qualified name to resolve.


def _no_import_model():
    class User(models.Model):
        # ok: python-pii-schema-field
        email = models.CharField(max_length=100)


def _no_import_add_field():
    # ok: python-pii-schema-field
    migrations.AddField(model_name="u", name="email", field=models.CharField(max_length=100))


def _no_import_create_model():
    # ok: python-pii-schema-field
    migrations.CreateModel(name="U", fields=[("email", models.CharField(max_length=100))])


from mylib import models  # noqa: E402


class HomeGrown(models.Model):
    # ok: python-pii-schema-field
    email = models.EmailField()


# Mid-file imports are the resolution gates under test: the near-misses
# above them stay silent.
import dataclasses  # noqa: E402

from django import forms  # noqa: E402
from django.conf import settings  # noqa: E402
from django.db import migrations, models  # noqa: E402,F811
from django.db.models import CharField, EmailField, Model  # noqa: E402
from pydantic import BaseModel  # noqa: E402
from rest_framework import serializers  # noqa: E402


class User(models.Model):
    # ruleid: python-pii-schema-field
    email = models.CharField(max_length=100)
    # ruleid: python-pii-schema-field
    phone_number = models.CharField(max_length=30)
    # ruleid: python-pii-schema-field
    first_name = models.CharField(max_length=30)
    # ruleid: python-pii-schema-field
    last_name = models.CharField(max_length=30)
    # ruleid: python-pii-schema-field
    ssn_last4 = models.CharField(max_length=4)
    # ruleid: python-pii-schema-field
    user_email = models.CharField(max_length=100)
    # ruleid: python-pii-schema-field
    userEmail = models.CharField(max_length=100)
    # ruleid: python-pii-schema-field
    email_address = models.CharField(max_length=100)
    # ruleid: python-pii-schema-field
    email_verified = models.BooleanField()
    # ruleid: python-pii-schema-field
    contact = models.EmailField()
    # ruleid: python-pii-schema-field
    email_plain = models.EmailField()
    # ok: python-pii-schema-field
    title = models.CharField(max_length=100)
    # ok: python-pii-schema-field
    slug = models.SlugField()
    # ok: python-pii-schema-field
    email_count = models.IntegerField()
    # ok: python-pii-schema-field
    email_verified_at = models.DateTimeField()
    # ok: python-pii-schema-field
    ssn_pattern = models.CharField(max_length=10)
    # ok: python-pii-schema-field
    phone_type = models.CharField(max_length=10)
    # ok: python-pii-schema-field
    email = models.ForeignKey(Email, on_delete=models.CASCADE)
    # ok: python-pii-schema-field
    ssn = models.ManyToManyField(Other, blank=True)
    # ok: python-pii-schema-field
    user_id = models.IntegerField()
    # ok: python-pii-schema-field
    title_verbose = models.CharField(verbose_name="email")
    # ok: python-pii-schema-field
    note = models.CharField(help_text="phone")


class Annotated(models.Model):
    # ruleid: python-pii-schema-field
    email: str = models.CharField(max_length=100)


class MultiBase(models.Model, object):
    # ruleid: python-pii-schema-field
    email = models.CharField(max_length=100)


class BareImport(Model):
    # ruleid: python-pii-schema-field
    email = CharField(max_length=100)
    # ruleid: python-pii-schema-field
    contact = EmailField()


EMAIL_HOST = "smtp.example.com"


def _settings_host():
    # ok: python-pii-schema-field
    return settings.EMAIL_HOST


class Plain:
    # ok: python-pii-schema-field
    email = models.CharField(max_length=100)


@dataclasses.dataclass
class DataPoint:
    # ok: python-pii-schema-field
    email = models.CharField(max_length=100)


class Profile(BaseModel):
    # ok: python-pii-schema-field
    email = models.CharField(max_length=100)


class ProfileSerializer(serializers.Serializer):
    # ok: python-pii-schema-field
    email = models.CharField(max_length=100)


class ProfileForm(forms.Form):
    # ok: python-pii-schema-field
    email = models.CharField(max_length=100)


def _stray_tuple():
    # ok: python-pii-schema-field
    return ("email", models.CharField(max_length=100))


def _add_phone():
    # ruleid: python-pii-schema-field
    migrations.AddField(model_name="u", name="phone_number", field=models.CharField(max_length=30))


def _add_slug():
    # ok: python-pii-schema-field
    migrations.AddField(model_name="u", name="slug", field=models.CharField(max_length=30))


def _add_email_field():
    # ruleid: python-pii-schema-field
    migrations.AddField(model_name="u", name="x", field=models.EmailField())


def _add_phone_multiline():
    migrations.AddField(
        model_name="user",
        name="phone_number",
        # ruleid: python-pii-schema-field
        field=models.CharField(max_length=30),
    )


def _remove_email():
    # ok: python-pii-schema-field
    migrations.RemoveField(model_name="u", name="email")


def _alter_email():
    # ok: python-pii-schema-field
    migrations.AlterField(model_name="u", name="email", field=models.EmailField())


def _rename_to_email():
    # ok: python-pii-schema-field
    migrations.RenameField(model_name="u", old_name="x", new_name="email")


def _create_single_line():
    # ruleid: python-pii-schema-field
    migrations.CreateModel(name="T", fields=[("email", models.CharField(max_length=100))])


def _create_user():
    migrations.CreateModel(
        name="User",
        fields=[
            ("id", models.AutoField(primary_key=True)),
            # ruleid: python-pii-schema-field
            ("email", models.CharField(max_length=100)),
            # ok: python-pii-schema-field
            ("title", models.CharField(max_length=100)),
        ],
    )
