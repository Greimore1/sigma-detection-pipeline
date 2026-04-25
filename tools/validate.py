from __future__ import annotations

import re
import sys
from common import iter_rule_paths, load_yaml, get_selection

REQUIRED_FIELDS = [
    "title", "id", "status", "description", "author", "date",
    "logsource", "detection", "falsepositives", "level", "tags",
]
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
ATTACK_TAG = re.compile(r"^attack\.t\d{4}(?:\.\d{3})?$", re.IGNORECASE)


def main() -> int:
    errors: list[str] = []
    ids: dict[str, str] = {}

    for path in iter_rule_paths():
        try:
            rule = load_yaml(path)
        except Exception as exc:
            errors.append(f"{path}: YAML parse failed: {exc}")
            continue

        for field in REQUIRED_FIELDS:
            if field not in rule or rule[field] in (None, "", []):
                errors.append(f"{path}: missing required field: {field}")

        rule_id = str(rule.get("id", ""))
        if rule_id:
            if rule_id in ids:
                errors.append(f"{path}: duplicate id also used by {ids[rule_id]}")
            ids[rule_id] = str(path)

        level = str(rule.get("level", "")).lower()
        if level and level not in VALID_LEVELS:
            errors.append(f"{path}: invalid level '{level}'")

        logsource = rule.get("logsource")
        if not isinstance(logsource, dict) or not any(k in logsource for k in ("product", "service", "category")):
            errors.append(f"{path}: logsource must define product, service, or category")

        tags = rule.get("tags", [])
        if not isinstance(tags, list) or not any(ATTACK_TAG.match(str(tag)) for tag in tags):
            errors.append(f"{path}: at least one MITRE ATT&CK tag is required")

        try:
            get_selection(rule)
        except Exception as exc:
            errors.append(f"{path}: unsupported detection structure: {exc}")

    if errors:
        print("Validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1

    print(f"Validation passed for {len(iter_rule_paths())} Sigma rules")
    return 0


if __name__ == "__main__":
    sys.exit(main())
