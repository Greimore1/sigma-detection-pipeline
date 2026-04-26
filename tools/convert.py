from __future__ import annotations

import re
from typing import Any
from common import iter_rule_paths, load_yaml, get_selection, DIST_DIR, rule_slug


def quote(value: Any) -> str:
    text = str(value).replace('"', '\\"')
    return f'"{text}"'


def condition_to_kql(field: str, expected: Any) -> str:
    safe_field = re.sub(r"[^A-Za-z0-9_\.]+", "_", field)
    if isinstance(expected, list):
        values = ", ".join(quote(item) for item in expected)
        return f"{safe_field} in ({values})"
    if isinstance(expected, str) and expected.startswith("contains:"):
        return f"{safe_field} contains {quote(expected.removeprefix('contains:'))}"
    return f"{safe_field} == {quote(expected)}"


def main() -> None:
    DIST_DIR.mkdir(parents=True, exist_ok=True)

    for rule_path in iter_rule_paths():
        rule = load_yaml(rule_path)
        selection = get_selection(rule)
        logsource = rule.get("logsource", {})
        table = logsource.get("service") or logsource.get("product") or "SecurityEvent"
        conditions = "\n| where ".join(condition_to_kql(field, expected) for field, expected in selection.items())
        kql = f"// {rule['title']}\n// Sigma ID: {rule['id']}\n{table}\n| where {conditions}\n"
        out = DIST_DIR / f"{rule_slug(rule_path)}.kql"
        out.write_text(kql, encoding="utf-8")
        print(f"Converted {rule_path} -> {out}")


if __name__ == "__main__":
    main()
