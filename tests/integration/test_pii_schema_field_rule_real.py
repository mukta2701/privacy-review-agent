"""Real-Semgrep tests for the PII schema-field rule.

Skipped when semgrep is absent. Covers every model, migration and
near-miss probe from the acceptance criteria through
``ReviewEngine().scan_files``, the Django import-resolution variants, and
the end-to-end non-blocking behaviour.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

needs_semgrep = pytest.mark.skipif(
    shutil.which("semgrep") is None, reason="semgrep not installed"
)

MODEL_IMPORTS = "from django.db import models"
MIGRATION_IMPORTS = "from django.db import migrations, models"


def _write_case(tmp_path: Path, name: str, code: str) -> Path:
    target = tmp_path / name
    target.write_text(code, encoding="utf-8")
    return target


def _semgrep_lines(result) -> set[int]:
    return {finding.line for finding in result.findings if finding.detector == "semgrep"}


@needs_semgrep
def test_model_sensitive_fields_match_and_plain_fields_do_not(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    target = _write_case(
        tmp_path,
        "model.py",
        MODEL_IMPORTS
        + "\n\n\nclass User(models.Model):\n"
        + "    email = models.CharField(max_length=100)\n"
        + "    phone_number = models.CharField(max_length=30)\n"
        + "    first_name = models.CharField(max_length=30)\n"
        + "    last_name = models.CharField(max_length=30)\n"
        + "    ssn_last4 = models.CharField(max_length=4)\n"
        + "    user_email = models.CharField(max_length=100)\n"
        + "    title = models.CharField(max_length=100)\n"
        + "    slug = models.SlugField()\n",
    )

    result = ReviewEngine().scan_files([target])

    assert _semgrep_lines(result) == {5, 6, 7, 8, 9, 10}


@needs_semgrep
def test_model_email_field_with_non_pii_name_matches_once(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    target = _write_case(
        tmp_path,
        "contact.py",
        MODEL_IMPORTS + "\n\n\nclass User(models.Model):\n    contact = models.EmailField()\n",
    )

    result = ReviewEngine().scan_files([target])

    assert _semgrep_lines(result) == {5}


@needs_semgrep
def test_add_field_sensitive_matches_and_slug_does_not(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    target = _write_case(
        tmp_path,
        "add.py",
        MIGRATION_IMPORTS
        + "\n\n\ndef _phone():\n"
        + '    migrations.AddField(\n        model_name="u", name="phone_number",\n'
        + "        field=models.CharField(max_length=30))\n"
        + "\n\ndef _slug():\n"
        + '    migrations.AddField(\n        model_name="u", name="slug",\n'
        + "        field=models.CharField(max_length=30))\n",
    )

    result = ReviewEngine().scan_files([target])

    assert _semgrep_lines(result) == {7}


@needs_semgrep
def test_add_field_email_field_matches(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    target = _write_case(
        tmp_path,
        "add_email.py",
        MIGRATION_IMPORTS
        + "\n\n\ndef _email():\n"
        + '    migrations.AddField(model_name="u", name="x", field=models.EmailField())\n',
    )

    result = ReviewEngine().scan_files([target])

    assert _semgrep_lines(result) == {5}


@needs_semgrep
def test_multiline_add_field_reports_on_field_line(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    target = _write_case(
        tmp_path,
        "add_multi.py",
        MIGRATION_IMPORTS
        + "\n\n\ndef _multi():\n"
        + "    migrations.AddField(\n"
        + '        model_name="user",\n'
        + '        name="phone_number",\n'
        + "        field=models.CharField(max_length=30),\n"
        + "    )\n",
    )

    result = ReviewEngine().scan_files([target])

    assert _semgrep_lines(result) == {8}


@needs_semgrep
def test_create_model_reports_only_email_tuple_line(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    target = _write_case(
        tmp_path,
        "create.py",
        MIGRATION_IMPORTS
        + "\n\n\ndef _create():\n"
        + "    migrations.CreateModel(\n"
        + '        name="Thing",\n'
        + "        fields=[\n"
        + '            ("id", models.AutoField(primary_key=True)),\n'
        + '            ("email", models.CharField(max_length=100)),\n'
        + '            ("title", models.CharField(max_length=100)),\n'
        + "        ],\n"
        + "    )\n",
    )

    result = ReviewEngine().scan_files([target])

    assert _semgrep_lines(result) == {9}


@needs_semgrep
def test_allowlisted_names_and_host_settings_produce_no_match(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    target = _write_case(
        tmp_path,
        "near_names.py",
        "from django.conf import settings\n"
        + MODEL_IMPORTS
        + "\n\n\nclass User(models.Model):\n"
        + "    email_count = models.IntegerField()\n"
        + "    email_verified_at = models.DateTimeField()\n"
        + "    ssn_pattern = models.CharField(max_length=10)\n"
        + "    phone_type = models.CharField(max_length=10)\n"
        + "\n\nEMAIL_HOST = \"smtp.example.com\"\n"
        + "host = settings.EMAIL_HOST\n",
    )

    result = ReviewEngine().scan_files([target])

    assert _semgrep_lines(result) == set()


@needs_semgrep
def test_non_django_classes_produce_no_match(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    target = _write_case(
        tmp_path,
        "non_model.py",
        "import dataclasses\n"
        + "from django import forms\n"
        + MODEL_IMPORTS
        + "\nfrom pydantic import BaseModel\n"
        + "from rest_framework import serializers\n"
        + "\n\n@dataclasses.dataclass\nclass DataPoint:\n"
        + "    email = models.CharField(max_length=100)\n"
        + "\n\nclass Profile(BaseModel):\n"
        + "    email = models.CharField(max_length=100)\n"
        + "\n\nclass ProfileSerializer(serializers.Serializer):\n"
        + "    email = models.CharField(max_length=100)\n"
        + "\n\nclass ProfileForm(forms.Form):\n"
        + "    email = models.CharField(max_length=100)\n"
        + "\n\nclass Plain:\n"
        + "    email = models.CharField(max_length=100)\n",
    )

    result = ReviewEngine().scan_files([target])

    assert _semgrep_lines(result) == set()


@needs_semgrep
def test_home_grown_models_produce_no_match(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    target = _write_case(
        tmp_path,
        "homegrown.py",
        "from mylib import models\n\n\nclass A(models.Model):\n    email = models.EmailField()\n",
    )

    result = ReviewEngine().scan_files([target])

    assert _semgrep_lines(result) == set()


@needs_semgrep
def test_remove_alter_and_rename_field_produce_no_match(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    target = _write_case(
        tmp_path,
        "other_ops.py",
        MIGRATION_IMPORTS
        + "\n\n\ndef _mig():\n"
        + '    migrations.RemoveField(model_name="u", name="email")\n'
        + '    migrations.AlterField(model_name="u", name="email", field=models.EmailField())\n'
        + '    migrations.RenameField(model_name="u", old_name="x", new_name="email")\n',
    )

    result = ReviewEngine().scan_files([target])

    assert _semgrep_lines(result) == set()


@needs_semgrep
def test_relation_and_opaque_fields_produce_no_match(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    target = _write_case(
        tmp_path,
        "relations.py",
        MODEL_IMPORTS
        + "\n\n\nclass Order(models.Model):\n"
        + "    email = models.ForeignKey(Email, on_delete=models.CASCADE)\n"
        + "    user_id = models.IntegerField()\n"
        + '    title = models.CharField(verbose_name="email")\n'
        + '    note = models.CharField(help_text="phone")\n',
    )

    result = ReviewEngine().scan_files([target])

    assert _semgrep_lines(result) == set()


@needs_semgrep
def test_django_import_variants_report(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    cases = [
        (
            "from django.db import models as m\n"
            "\n\nclass U(m.Model):\n    contact = m.EmailField()\n",
            {5},
        ),
        (
            "from django.db.models import Model, EmailField\n"
            "\n\nclass U(Model):\n    contact = EmailField()\n",
            {5},
        ),
        (
            "import django.db.models\n\n\nclass U(django.db.models.Model):\n"
            "    email = django.db.models.CharField(max_length=100)\n",
            {5},
        ),
    ]
    for number, (code, expected) in enumerate(cases):
        target = _write_case(tmp_path, f"variant_{number}.py", code)

        result = ReviewEngine().scan_files([target])

        assert _semgrep_lines(result) == expected


@needs_semgrep
def test_missing_django_import_produces_no_match(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    target = _write_case(
        tmp_path,
        "no_import.py",
        "class A(models.Model):\n    email = models.EmailField()\n",
    )

    result = ReviewEngine().scan_files([target])

    assert _semgrep_lines(result) == set()


@needs_semgrep
def test_end_to_end_finding_is_confirmed_medium_non_blocking(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    target = _write_case(
        tmp_path,
        "app.py",
        MODEL_IMPORTS
        + "\n\n\nclass User(models.Model):\n"
        + "    email = models.CharField(max_length=100)\n",
    )

    result = ReviewEngine().scan_files([target], changed_map={str(target): {5}})

    semgrep_hits = [finding for finding in result.findings if finding.detector == "semgrep"]
    assert len(semgrep_hits) == 1
    hit = semgrep_hits[0]
    assert hit.line == 5
    assert hit.tier.value == "confirmed"
    assert hit.category == "PII_SCHEMA_FIELD"
    assert hit.severity.value == "medium"
    assert hit.confidence.value == "high"
    assert hit.blocking is False
