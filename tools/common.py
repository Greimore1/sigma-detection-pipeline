from __future__ import annotations

from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "rules"
TESTS_DIR = ROOT / "tests"
DIST_DIR = ROOT / "dist" / "kql"


def _parse_scalar(value: str) -> Any:
    value = value.strip()
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    if value.startswith("'") and value.endswith("'"):
        return value[1:-1]
    return value


def load_yaml(path: Path) -> dict[str, Any]:
    """Tiny YAML parser for this MVP's simple Sigma subset."""
    raw_lines = [line.rstrip("\n") for line in path.read_text(encoding="utf-8").splitlines()]
    lines = []
    for raw in raw_lines:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        lines.append((indent, raw.strip()))

    root: dict[str, Any] = {}
    stack: list[tuple[int, Any]] = [(-1, root)]

    for idx, (indent, line) in enumerate(lines):
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]

        if line.startswith("- "):
            if not isinstance(parent, list):
                raise ValueError(f"List item found without list parent in {path}: {line}")
            parent.append(_parse_scalar(line[2:]))
            continue

        if ":" not in line:
            raise ValueError(f"Unsupported YAML line in {path}: {line}")

        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if not isinstance(parent, dict):
            raise ValueError(f"Mapping found under non-mapping parent in {path}: {line}")

        if value == "":
            next_line = lines[idx + 1] if idx + 1 < len(lines) else None
            if next_line and next_line[0] > indent and next_line[1].startswith("- "):
                container: Any = []
            else:
                container = {}
            parent[key] = container
            stack.append((indent, container))
        else:
            parent[key] = _parse_scalar(value)

    return root


def iter_rule_paths() -> list[Path]:
    return sorted(RULES_DIR.rglob("*.yml"))


def rule_slug(path: Path) -> str:
    return path.stem


def get_selection(rule: dict[str, Any]) -> dict[str, Any]:
    detection = rule.get("detection", {})
    condition = detection.get("condition")
    if condition != "selection":
        raise ValueError("MVP runner only supports condition: selection")
    selection = detection.get("selection")
    if not isinstance(selection, dict):
        raise ValueError("Rule must contain detection.selection mapping")
    return selection
