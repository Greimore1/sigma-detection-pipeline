from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any
from common import iter_rule_paths, load_yaml, get_selection, TESTS_DIR, rule_slug


def _normalise(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True).lower()
    return str(value).lower()


def _field_matches(event_value: Any, expected: Any) -> bool:
    actual = _normalise(event_value)
    if isinstance(expected, list):
        return any(_field_matches(event_value, item) for item in expected)
    if isinstance(expected, str) and expected.startswith("contains:"):
        return expected.removeprefix("contains:").lower() in actual
    return actual == _normalise(expected)


def matches(rule: dict[str, Any], event: dict[str, Any]) -> bool:
    selection = get_selection(rule)
    for field, expected in selection.items():
        if field not in event:
            return False
        if not _field_matches(event[field], expected):
            return False
    return True


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"{path} did not parse to a JSON object")
    return data


def main() -> int:
    failures: list[str] = []

    for rule_path in iter_rule_paths():
        slug = rule_slug(rule_path)
        test_dir = TESTS_DIR / slug
        positive = test_dir / "positive.json"
        negative = test_dir / "negative.json"
        if not positive.exists() or not negative.exists():
            failures.append(f"{slug}: expected {positive} and {negative}")
            continue

        rule = load_yaml(rule_path)
        positive_event = load_json(positive)
        negative_event = load_json(negative)

        if not matches(rule, positive_event):
            failures.append(f"{slug}: positive.json did not match")
        else:
            print(f"PASS: {slug} matched positive.json")

        if matches(rule, negative_event):
            failures.append(f"{slug}: negative.json unexpectedly matched")
        else:
            print(f"PASS: {slug} did not match negative.json")

    if failures:
        print("\nRule tests failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("\nAll rule tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
