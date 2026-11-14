# Calibration

Run:

```bash
privacy-review-agent calibrate --fixture-set tests/fixtures
```

## Release gate

`calibrate` exits 0 on a pass and exits 2 unless all of these hold:

- Near-miss precision above 0.90
- Corpus recall at least 0.80, with known-gap cases excluded
- Deterministic output is true
- Every current unsafe fixture file is still detected
  (fixture recall equals 1.0)
- Every Semgrep rule test passes (only when Semgrep is installed;
  with Semgrep absent this condition and its output key do not exist)

The old fixture precision check (0.85 and above) is gone.
It is replaced by the near-miss precision check.
Exit 1 still means a runtime error, as before.

## Near-miss precision

Near-miss precision is the share of `near_miss` corpus cases that
produce no finding at all. Each near-miss case is one trial, and a
clean line counts as a correct "no finding" verdict.

## Corpus format

The corpus lives at `tests/fixtures/labelled/cases.jsonl`, next to
`safe/` and `unsafe/` under the same fixture set, so `--fixture-set`
keeps working. It holds one JSON object per line. Each case has:

- `id`: unique, stable (for example `nm-001`)
- `ext`: one of `py`, `js`, `ts`
- `text_b64`: the single source line, base64 (standard alphabet, UTF-8)
- `expect`: the list of detectors the line must trigger
  (empty for a near-miss)
- `kind`: `near_miss` or `true`
- `tags`: a list, which may contain `known_gap`

Case text is stored base64-only so the committed file stays inert to
the repo's own privacy scan and the secret pre-commit hook.

## Inspecting cases

Case text is base64 (UTF-8). Decode one case like this:

```bash
python3 - <<'EOF'
import base64
import json

target = "nm-001"
for row in open("tests/fixtures/labelled/cases.jsonl"):
    case = json.loads(row)
    if case["id"] == target:
        raw = base64.b64decode(case["text_b64"]).decode("utf-8")
        print(case["kind"], case["expect"])
        print(raw)
EOF
```

## Adding a case

1. Write one source line with a single intended verdict.
2. Label it from the intended meaning: the detector list it must
   trigger, or an empty list for a near-miss.
3. Encode the line (UTF-8, standard base64, no newlines).
4. Append one JSON object per line with keys
   `id`, `ext`, `text_b64`, `expect`, `kind` and `tags`.

Label from meaning, never from current output. Never drop, relabel
or reword a near-miss to move the gate.

## Known gaps

Cases tagged `known_gap` cover matcher limits that stay out of scope:
plural field forms and run-together lowercase names.
They carry the detector they should trigger once the matcher is
fixed. They show up in `known_gap_misses` but stay out of the gated
recall numbers, so a future matcher fix turns misses into hits
without moving the gate.

## Output keys

The JSON output keeps the fixture-based keys (`precision`, `recall`,
`deterministic`, `tp`, `fp`, `unsafe_file_count`) and adds:

- `overall_precision`: `tp / (tp + fp)` over the corpus
- `overall_recall`: `tp / (tp + fn)` over the corpus
- `near_miss_precision`: share of near-miss cases with no finding
- `near_miss_count`, `true_case_count`, `known_gap_count`
- `detectors`: one entry per detector name, each with precision,
  recall, `tp`, `fp` and `fn`
- `known_gap_misses`: the sorted list of missed known-gap case ids
- `semgrep_rule_tests`: the rule-test harness result (`rules`, `cases`,
  `failures`), only when Semgrep is installed

A zero denominator counts as 1.0. Floats are rounded to 4 decimals.
Two runs produce byte-identical output: no temp paths, timestamps
or other run-dependent values appear.

## Semgrep rule tests

Each rule file `<name>.yaml` under the Semgrep rules directory is tested
against its sibling case files (`<name>.py`, `<name>.js`, `<name>.ts`). A
case is the line after a `# ruleid: <id>` (or `// ruleid: <id>`) comment,
which the rule must match, or after a `# ok: <id>` comment, which the rule
must not match. The harness also checks that every rule has valid metadata
(category from `policies/taxonomy.yaml`, severity
`critical|high|medium|low`, confidence `high|medium|low`, non-empty
remediation). Any violation fails the release gate: `calibrate` exits 2 with
a `"semgrep rule tests: ..."` entry in its gate failures.
