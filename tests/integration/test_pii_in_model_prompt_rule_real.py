"""Real-Semgrep tests for the PII-in-model-prompt rule.

Skipped when semgrep is absent. Covers every positive and near-miss probe
from the acceptance criteria through ``ReviewEngine().scan_files``, plus the
end-to-end blocking and keyword-shadowing behaviour.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

needs_semgrep = pytest.mark.skipif(
    shutil.which("semgrep") is None, reason="semgrep not installed"
)

# Each block is one probe; the sink (match) line is at the given offset.
POSITIVE_BLOCKS: list[tuple[str, int]] = [
    ('client.chat.completions.create(model=m, messages=[{"role": "user", "content": user.email}])', 0),
    ("client.responses.create(model=m, input=user.phone)", 0),
    ('client.messages.create(model=m, max_tokens=1, messages=[{"role": "user", "content": f"hi {user.email}"}])', 0),
    ("model.generate_content(user.ssn)", 0),
    ('client.models.generate_content(model=m, contents=user.first_name)', 0),
    ('client.chat.completions.create(model=m, messages=f"hi {user.email}")', 0),
    ('client.chat.completions.create(model=m, messages="hi {}".format(user.email))', 0),
    ('client.chat.completions.create(model=m, messages="hi %s" % user.email)', 0),
    ('client.chat.completions.create(model=m, messages="hi " + user.email)', 0),
    ('client.chat.completions.create(model=m, messages="".join(["hi ", user.email]))', 0),
    ("prompt = user.email\nclient.chat.completions.create(model=m, messages=prompt)", 1),
    ('msgs = [{"role": "user", "content": user.email}]\nclient.chat.completions.create(model=m, messages=msgs)', 1),
    ("client.responses.create(model=m, input=user.email)", 0),
    ("client.models.generate_content(model=m, contents=user.email)", 0),
    ("client.chat.completions.create(model=m, system=user.email)", 0),
    ("client.chat.completions.create(model=m, prompt=user.email)", 0),
    ("async def _f():\n    await client.chat.completions.create(model=m, messages=[{\"role\": \"user\", \"content\": user.email}])", 1),
    ("chat = model.start_chat()\nchat.send_message(user.email)", 1),
    ("chat = client.chats.create(model=m)\nchat.send_message(user.email)", 1),
    ("client.chat.completions.create(model=m, messages=user.phone_number)", 0),
    ("client.chat.completions.create(model=m, messages=user.emailVerified)", 0),
    ('client.beta.chat.completions.stream(model=m, messages=[{"role": "user", "content": user.email}])', 0),
    ("client.responses.parse(model=m, input=user.email)", 0),
    ("client.completions.create(model=m, prompt=user.email)", 0),
    ('client.messages.stream(model=m, messages=[{"role": "user", "content": user.email}])', 0),
]

NEAR_MISS_BLOCKS: list[str] = [
    'client.chat.completions.create(model=m, messages=[{"role": "user", "content": user.id}])',
    "client.chat.completions.create(model=m, messages=email_count)",
    "client.chat.completions.create(model=m, messages=settings.EMAIL_HOST)",
    "client.chat.completions.create(model=m, messages=ssn_pattern)",
    "client.chat.completions.create(model=m, messages=redact(user.email))",
    "client.chat.completions.create(model=m, messages=util.mask(user.email))",
    "client.chat.completions.create(model=m, messages=hash(user.email))",
    "client.chat.completions.create(model=m, messages=tokenize(user.email))",
    "client.chat.completions.create(model=m, messages=len(user.email))",
    "client.chat.completions.create(model=m, messages=(user.email is None))",
    "client.chat.completions.create(model=m, messages=(user.email == other))",
    "client.chat.completions.create(model=m, messages=email.utils.formatdate())",
    "Model.objects.create(email=user.email)",
    'client.messages.create(to=user.phone, body="hi")',
    "pending = user.email",
    "bot.send_message(chat_id, user.email)",
    "other = make_bot()\nother.send_message(user.email)",
    'openai.ChatCompletion.create(messages=[{"content": user.email}])',
    "client.chat.completions.create(model=m, messages=user.email_count)",
    "client.chat.completions.create(model=m, messages=user.email_domain)",
    "client.chat.completions.create(model=m, messages=user.phone_type)",
    "client.chat.completions.create(model=m, messages=emails)",
    "client.chat.completions.create(model=m, messages=useremail)",
]


def _write_blocks(tmp_path: Path, name: str, blocks: list[str]) -> Path:
    target = tmp_path / name
    target.write_text("\n".join(blocks) + "\n", encoding="utf-8")
    return target


@needs_semgrep
def test_every_positive_probe_matches_at_its_sink_line(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    lines: list[str] = []
    expected: set[int] = set()
    for block, offset in POSITIVE_BLOCKS:
        expected.add(len(lines) + offset + 1)
        lines.extend(block.splitlines())
    target = _write_blocks(tmp_path, "positives.py", lines)

    result = ReviewEngine().scan_files([target])

    matched = {
        finding.line for finding in result.findings if finding.detector == "semgrep"
    }
    assert matched == expected


@needs_semgrep
def test_no_near_miss_probe_matches(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    target = _write_blocks(tmp_path, "near_miss.py", NEAR_MISS_BLOCKS)

    result = ReviewEngine().scan_files([target])

    assert not [finding for finding in result.findings if finding.detector == "semgrep"]


@needs_semgrep
def test_end_to_end_finding_is_confirmed_blocking_and_shadows_keyword(tmp_path):
    from privacy_review_agent.engine import ReviewEngine

    target = tmp_path / "app.py"
    target.write_text(
        'client.messages.create(model=m, max_tokens=1, messages=[{"role": "user", "content": user.email}])\n',
        encoding="utf-8",
    )

    result = ReviewEngine().scan_files([target], changed_map={str(target): {1}})

    semgrep_hits = [f for f in result.findings if f.detector == "semgrep"]
    assert len(semgrep_hits) == 1
    hit = semgrep_hits[0]
    assert hit.tier.value == "confirmed"
    assert hit.category == "PII_IN_MODEL_PROMPT"
    assert hit.blocking is True
    assert not any(
        f.detector == "pii_in_prompts" and f.line == 1 for f in result.findings
    )
