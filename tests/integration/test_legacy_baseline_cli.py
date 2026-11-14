"""Legacy baselines, warnings and baseline migrate (Phase 1)."""

from __future__ import annotations

import json
from hashlib import sha256

from click.testing import CliRunner

from privacy_review_agent.cli import main

SECRET_LINE = 'API_KEY = "sk_test_12345678901234567890"'
MESSAGE = "Potential hardcoded secret detected"


def _old_key(path: str) -> str:
    return "|".join(["secrets", "SECRET_EXPOSURE", path, "1", MESSAGE, SECRET_LINE])


def _new_key(path: str) -> str:
    return "|".join(["secrets", "SECRET_EXPOSURE", path, SECRET_LINE, "1"])


def _legacy_hash(path: str) -> str:
    return sha256(_old_key(path).encode("utf-8")).hexdigest()[:16]


def _new_hash(path: str) -> str:
    return sha256(_new_key(path).encode("utf-8")).hexdigest()[:16]


def _write_secret(target) -> None:
    target.write_text(f"{SECRET_LINE}\n")


def _scan(args) -> object:
    return CliRunner().invoke(main, ["scan", *args])


def test_legacy_baseline_unblocks_but_versioned_does_not(tmp_path):
    target = tmp_path / "hardcoded.py"
    _write_secret(target)

    legacy = tmp_path / "legacy.json"
    legacy.write_text(json.dumps({"fingerprints": [_legacy_hash(str(target))]}))
    assert _scan(["--path", str(target), "--baseline-file", str(legacy)]).exit_code == 0

    versioned = tmp_path / "versioned.json"
    versioned.write_text(
        json.dumps({"fingerprint_version": 2, "fingerprints": [_legacy_hash(str(target))]})
    )
    assert _scan(["--path", str(target), "--baseline-file", str(versioned)]).exit_code == 2

    missing = tmp_path / "missing.json"
    assert _scan(["--path", str(target), "--baseline-file", str(missing)]).exit_code == 2


def test_legacy_baseline_warns_on_stderr(tmp_path):
    target = tmp_path / "hardcoded.py"
    _write_secret(target)

    legacy = tmp_path / "legacy.json"
    legacy.write_text(json.dumps({"fingerprints": [_legacy_hash(str(target))]}))
    with_legacy = _scan(["--path", str(target), "--baseline-file", str(legacy)])
    assert "baseline migrate" in with_legacy.stderr
    assert "baseline migrate" not in with_legacy.stdout

    versioned = tmp_path / "versioned.json"
    versioned.write_text(
        json.dumps(
            {
                "fingerprint_version": 2,
                "fingerprints": [_new_hash(str(target))],
            }
        )
    )
    with_versioned = _scan(["--path", str(target), "--baseline-file", str(versioned)])
    assert "baseline migrate" not in with_versioned.stderr

    missing = tmp_path / "missing.json"
    no_baseline = _scan(["--path", str(target), "--baseline-file", str(missing)])
    assert "baseline migrate" not in no_baseline.stderr


def test_json_output_has_no_legacy_fingerprint(tmp_path):
    target = tmp_path / "hardcoded.py"
    _write_secret(target)
    result = _scan(["--path", str(target), "--format", "json"])
    assert "legacy_fingerprint" not in result.output
    sarif = _scan(["--path", str(target), "--format", "sarif"])
    assert "legacy_fingerprint" not in sarif.output
    md = _scan(["--path", str(target), "--format", "md"])
    assert "legacy_fingerprint" not in md.output


def test_baseline_create_writes_version_2(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(main, ["baseline", "create"])
    assert result.exit_code == 0
    payload = json.loads((tmp_path / ".privacy-review-baseline.json").read_text())
    assert payload["fingerprint_version"] == 2
    assert payload["count"] == len(payload["fingerprints"])


def test_baseline_migrate_converts_legacy_file(tmp_path, monkeypatch):
    target = tmp_path / "hardcoded.py"
    _write_secret(target)
    monkeypatch.chdir(tmp_path)

    # `baseline migrate` scans the working tree by relative path, so the
    # legacy entry must use the path string the engine sees.
    scanned = "hardcoded.py"
    legacy_hash = _legacy_hash(scanned)
    baseline = tmp_path / ".privacy-review-baseline.json"
    baseline.write_text(
        json.dumps(
            {
                "created_from_ref": "HEAD",
                "fingerprints": [legacy_hash, "deadbeefdeadbeef"],
            }
        )
    )

    result = CliRunner().invoke(main, ["baseline", "migrate"])
    assert result.exit_code == 0
    assert "1 migrated" in result.output
    assert "1 dropped" in result.output

    payload = json.loads(baseline.read_text())
    assert payload["fingerprint_version"] == 2
    assert payload["fingerprints"] == [_new_hash(scanned)]
    assert payload["count"] == 1
    assert payload["created_from_ref"] == "HEAD"

    follow_up = _scan(["--path", scanned, "--baseline-file", str(baseline)])
    assert follow_up.exit_code == 0
    assert "baseline migrate" not in follow_up.stderr


def test_baseline_migrate_output_flag_leaves_input_alone(tmp_path, monkeypatch):
    target = tmp_path / "hardcoded.py"
    _write_secret(target)
    monkeypatch.chdir(tmp_path)

    baseline = tmp_path / "legacy.json"
    original = json.dumps({"fingerprints": [_legacy_hash("hardcoded.py")]})
    baseline.write_text(original)
    other = tmp_path / "migrated.json"

    result = CliRunner().invoke(
        main, ["baseline", "migrate", "--baseline-file", str(baseline), "--output", str(other)]
    )
    assert result.exit_code == 0
    assert baseline.read_text() == original
    payload = json.loads(other.read_text())
    assert payload["fingerprint_version"] == 2
    assert payload["fingerprints"] == [_new_hash("hardcoded.py")]


def test_baseline_migrate_refuses_versioned_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    baseline = tmp_path / "versioned.json"
    original = json.dumps({"fingerprint_version": 2, "fingerprints": ["abc"]})
    baseline.write_text(original)

    result = CliRunner().invoke(
        main, ["baseline", "migrate", "--baseline-file", str(baseline)]
    )
    assert result.exit_code != 0
    assert baseline.read_text() == original

    missing = CliRunner().invoke(
        main, ["baseline", "migrate", "--baseline-file", str(tmp_path / "nope.json")]
    )
    assert missing.exit_code != 0
