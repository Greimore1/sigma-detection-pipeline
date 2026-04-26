from __future__ import annotations

import re
from typing import Any
from common import iter_rule_paths, load_yaml, get_selection, DIST_DIR, rule_slug

# Maps (product, category) logsource pairs to Defender for Endpoint table names
TABLE_MAP: dict[tuple[str, str], str] = {
    ("windows", "process_creation"): "DeviceProcessEvents",
}

# Maps Sigma/Sysmon field names to DeviceProcessEvents field names
FIELD_MAP: dict[str, dict[str, str]] = {
    "DeviceProcessEvents": {
        "Image": "FolderPath",
        "CommandLine": "ProcessCommandLine",
        "ParentImage": "InitiatingProcessFolderPath",
        "User": "AccountName",
    }
}


def quote(value: Any) -> str:
    text = str(value).replace('"', '\\"')
    return f'"{text}"'


def condition_to_kql(field: str, expected: Any, field_map: dict[str, str]) -> str:
    mapped_field = field_map.get(field, re.sub(r"[^A-Za-z0-9_\.]+", "_", field))
    if isinstance(expected, list):
        values = ", ".join(quote(item) for item in expected)
        return f"{mapped_field} in ({values})"
    if isinstance(expected, str) and expected.startswith("contains:"):
        return f"{mapped_field} contains {quote(expected.removeprefix('contains:'))}"
    return f"{mapped_field} == {quote(expected)}"


def main() -> None:
    DIST_DIR.mkdir(parents=True, exist_ok=True)

    for rule_path in iter_rule_paths():
        rule = load_yaml(rule_path)
        selection = get_selection(rule)
        logsource = rule.get("logsource", {})
        product = logsource.get("product", "")
        category = logsource.get("category", "")
        table = TABLE_MAP.get((product, category)) or logsource.get("service") or product or "SecurityEvent"
        field_map = FIELD_MAP.get(table, {})
        conditions = "\n| where ".join(condition_to_kql(f, v, field_map) for f, v in selection.items())
        kql = f"// {rule['title']}\n// Sigma ID: {rule['id']}\n{table}\n| where {conditions}\n"
        out = DIST_DIR / f"{rule_slug(rule_path)}.kql"
        out.write_text(kql, encoding="utf-8")
        print(f"Converted {rule_path} -> {out}")


if __name__ == "__main__":
    main()
