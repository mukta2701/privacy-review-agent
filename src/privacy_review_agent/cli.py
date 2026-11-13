from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import click

from privacy_review_agent.config import load_settings
from privacy_review_agent.engine import ReviewEngine
from privacy_review_agent.reporters import render_json, render_markdown, render_sarif


def _collect_files(paths: list[Path]) -> list[Path]:
    out: list[Path] = []
    for path in paths:
        if path.is_file():
            out.append(path)
            continue
        if path.is_dir():
            for item in path.rglob("*"):
                if item.is_file() and ".git" not in item.parts:
                    out.append(item)
    return out


def _load_baseline(path: Path) -> set[str]:
    if not path.exists():
        return set()
    raw = json.loads(path.read_text(encoding="utf-8"))
    return set(raw.get("fingerprints", []))


def _emit(content: str, output: str | None) -> None:
    if output:
        Path(output).write_text(content, encoding="utf-8")
    else:
        click.echo(content)


@click.group()
@click.version_option(version="0.1.0", prog_name="privacy-review-agent")
def main() -> None:
    """Privacy review agent CLI."""


@main.command()
@click.option("--base-ref", default="origin/main")
@click.option("--head-ref", default="HEAD")
@click.option("--path", "paths", multiple=True, type=click.Path(path_type=Path))
@click.option("--format", "fmt", type=click.Choice(["json", "sarif", "md"]), default="md")
@click.option("--output", default="")
@click.option(
    "--baseline-file",
    default=".privacy-review-baseline.json",
    type=click.Path(path_type=Path),
)
@click.option("--policies-dir", type=click.Path(path_type=Path), default=None)
@click.option("--offline/--online", default=True)
@click.option("--allow-verifier-egress", is_flag=True, default=False)
def scan(
    base_ref: str,
    head_ref: str,
    paths: tuple[Path, ...],
    fmt: str,
    output: str,
    baseline_file: Path,
    policies_dir: Path | None,
    offline: bool,
    allow_verifier_egress: bool,
) -> None:
    settings = load_settings(policies_dir=policies_dir)
    settings.offline_mode = offline
    settings.allow_verifier_egress = allow_verifier_egress
    engine = ReviewEngine(settings=settings)

    baseline = _load_baseline(baseline_file)

    if paths:
        files = _collect_files(list(paths))
        result = engine.scan_files(files, baseline_fingerprints=baseline)
    else:
        result = engine.scan_ref(base_ref, head_ref, baseline_fingerprints=baseline)

    if fmt == "json":
        content = render_json(result)
    elif fmt == "sarif":
        content = render_sarif(result)
    else:
        content = render_markdown(result)

    _emit(content, output or None)

    if result.blocking_findings():
        raise SystemExit(2)


@main.group()
def baseline() -> None:
    """Baseline management commands."""


@baseline.command("create")
@click.option("--ref", default="HEAD")
@click.option("--output", default=".privacy-review-baseline.json")
def baseline_create(ref: str, output: str) -> None:
    _ = ref
    engine = ReviewEngine()
    files = _collect_files([Path(".")])
    result = engine.scan_files(files)
    payload = {
        "created_from_ref": ref,
        "fingerprints": sorted([finding.fingerprint for finding in result.findings]),
        "count": len(result.findings),
    }
    Path(output).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    click.echo(f"Baseline written: {output} ({payload['count']} fingerprints)")


@main.command("enforce-rerun-approval")
@click.option("--required-label", default="privacy-rerun-approved")
def enforce_rerun_approval(required_label: str) -> None:
    security_team_slug = os.getenv("SECURITY_TEAM_SLUG", "")
    if not security_team_slug:
        click.echo("Fail-closed: SECURITY_TEAM_SLUG is not configured.")
        raise SystemExit(2)

    event_path = os.getenv("GITHUB_EVENT_PATH", "")
    if not event_path:
        click.echo("Fail-closed: GITHUB_EVENT_PATH not available for label validation.")
        raise SystemExit(2)

    data = json.loads(Path(event_path).read_text(encoding="utf-8"))
    labels = [
        label.get("name", "")
        for label in data.get("pull_request", {}).get("labels", [])
        if isinstance(label, dict)
    ]

    if required_label not in labels:
        click.echo(f"Required rerun approval label '{required_label}' is missing.")
        raise SystemExit(2)

    click.echo("Rerun approval label present.")


@main.command()
@click.option("--fixture-set", type=click.Path(path_type=Path), default=Path("tests/fixtures"))
def calibrate(fixture_set: Path) -> None:
    engine = ReviewEngine()
    try:
        metrics = engine.run_calibration(fixture_set)
    except (OSError, ValueError) as exc:
        click.echo(f"calibration failed: {exc}", err=True)
        raise SystemExit(1)
    payload = metrics.to_dict()
    click.echo(json.dumps(payload, indent=2, sort_keys=True))

    if metrics.gate_failures():
        raise SystemExit(2)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        click.echo(f"Runtime error: {exc}", err=True)
        sys.exit(1)
