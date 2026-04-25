# Sigma Detection Pipeline

A lightweight detection-as-code pipeline that treats security rules as version-controlled, testable engineering artifacts.

## What it does

- Validates Sigma rule structure and metadata on every push and pull request
- Runs positive and negative unit tests against each rule
- Fails the CI build if any rule is malformed or a test doesn't pass

## Project structure

```
.github/workflows/ci.yml   # GitHub Actions pipeline
rules/                     # Sigma detection rules (YAML)
tests/                     # Per-rule positive and negative test events (JSON)
tools/
  common.py                # Shared utilities and YAML parser
  validate.py              # Rule metadata validation
  test_rules.py            # Unit test runner
```

## Running locally

No dependencies required — pure Python 3.

```bash
python tools/validate.py
python tools/test_rules.py
```

## Adding a rule

1. Add a `.yml` file under `rules/<platform>/`
2. Add `tests/<rule_name>/positive.json` and `tests/<rule_name>/negative.json`
3. Open a PR — CI will validate and test it automatically

## Roadmap

- **v1.1** — KQL conversion for Microsoft Sentinel, detection coverage report
- **v2.0** — Multi-platform rule support, pySigma backend integration, ATT&CK Navigator export
