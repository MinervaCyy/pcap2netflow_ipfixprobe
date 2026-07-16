#!/usr/bin/env python3
"""Validate the frozen CICIDS2018 pilot rules, counts, and UTC anchors."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RULES_PATH = ROOT / "configs/rules_2018.yaml"
COUNTS_PATH = ROOT / "tests/expected/cicids2018_pilot_counts.json"
ANCHORS_PATH = ROOT / "configs/cicids2018_pilot_timezone_anchors.yaml"

EXPECTED_DAYS = {
    "Wednesday-14-02-2018",
    "Thursday-15-02-2018",
    "Thursday-22-02-2018",
}

EXPECTED_SOURCE = {
    "repository": "https://github.com/GintsEngelen/CNS2022_Code.git",
    "commit": "f0ce502818e59e6cd062720ab2286c5ff6f2bdec",
    "notebook": "Labelling/CICIDS2018_labelling_fixed_CICFlowMeter.ipynb",
}


def fail(message: str) -> None:
    raise SystemExit(f"ERROR: {message}")


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail(f"missing file: {path.relative_to(ROOT)}")
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON-compatible YAML in {path.relative_to(ROOT)}: {exc}")

    if not isinstance(value, dict):
        fail(f"top-level value must be an object: {path.relative_to(ROOT)}")
    return value


def iso_utc(epoch_ns: int) -> str:
    seconds, remainder_ns = divmod(epoch_ns, 1_000_000_000)
    dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
    if remainder_ns:
        fraction = f"{remainder_ns:09d}".rstrip("0")
        return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{fraction}Z"
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def expected_midnight_ns(day: str) -> int:
    parts = day.split("-")
    if len(parts) != 4:
        fail(f"invalid day identifier: {day}")
    date_value = datetime.strptime("-".join(parts[1:]), "%d-%m-%Y")
    return int(date_value.replace(tzinfo=timezone.utc).timestamp()) * 1_000_000_000


def main() -> None:
    rules = load_json(RULES_PATH)
    counts = load_json(COUNTS_PATH)
    anchors = load_json(ANCHORS_PATH)

    for name, document in (
        ("rules", rules),
        ("counts", counts),
        ("anchors", anchors),
    ):
        if document.get("schema_version") != "1.0":
            fail(f"{name}: unsupported schema_version")
        if document.get("source") != EXPECTED_SOURCE:
            fail(f"{name}: source pin mismatch")

    semantics = rules.get("semantics", {})
    if semantics.get("timestamp_timezone") != "UTC":
        fail("rules: timestamp timezone must be UTC")
    if semantics.get("timestamp_unit") != "nanoseconds since Unix epoch":
        fail("rules: timestamp unit mismatch")
    if semantics.get("interval_bounds") != "inclusive":
        fail("rules: interval bounds must be inclusive")
    if semantics.get("rule_application") != "ordered":
        fail("rules: rule application must be ordered")

    rule_schema = rules.get("rule_schema", {})
    required = rule_schema.get("required")
    supported_operators = set(rule_schema.get("supported_operators", []))

    if not isinstance(required, list) or not required:
        fail("rules: rule_schema.required must be a non-empty list")
    if "day" in required:
        fail("rules: day belongs to the parent day object, not each rule")
    if not supported_operators:
        fail("rules: no supported operators declared")

    day_entries = rules.get("days")
    if not isinstance(day_entries, list):
        fail("rules: days must be a list")

    rule_days = {entry.get("day") for entry in day_entries}
    if rule_days != EXPECTED_DAYS:
        fail(f"rules: pilot-day set mismatch: {sorted(rule_days)}")

    rule_windows: dict[str, list[tuple[int, int]]] = {}
    rule_ids: set[str] = set()
    observed_operators: set[str] = set()

    for day_entry in day_entries:
        day = day_entry["day"]
        day_rules = day_entry.get("rules")

        if not isinstance(day_rules, list) or not day_rules:
            fail(f"{day}: rules must be a non-empty list")

        orders = [rule.get("order") for rule in day_rules]
        if orders != list(range(1, len(day_rules) + 1)):
            fail(f"{day}: rule order is not contiguous from 1")

        windows: list[tuple[int, int]] = []

        for rule in day_rules:
            missing = [field for field in required if field not in rule]
            if missing:
                fail(f"{day}/{rule.get('id', '<unknown>')}: missing {missing}")

            rule_id = rule["id"]
            if rule_id in rule_ids:
                fail(f"duplicate rule id: {rule_id}")
            rule_ids.add(rule_id)

            start_ns = rule["start_ns"]
            end_ns = rule["end_ns"]
            if not isinstance(start_ns, int) or not isinstance(end_ns, int):
                fail(f"{day}/{rule_id}: timestamps must be integers")
            if start_ns > end_ns:
                fail(f"{day}/{rule_id}: start_ns exceeds end_ns")

            window = (start_ns, end_ns)
            if window not in windows:
                windows.append(window)

            additional_filter = rule["additional_filter"]
            if additional_filter is not None:
                filter_type = additional_filter.get("type")
                if filter_type not in {"all_of", "any_of"}:
                    fail(f"{day}/{rule_id}: invalid additional filter type")

                conditions = additional_filter.get("conditions")
                if not isinstance(conditions, list) or not conditions:
                    fail(f"{day}/{rule_id}: empty additional filter")

                for condition in conditions:
                    operator = condition.get("operator")
                    observed_operators.add(operator)
                    if operator not in supported_operators:
                        fail(
                            f"{day}/{rule_id}: undeclared operator {operator!r}"
                        )

                    value = condition.get("value")
                    if operator == "not_in":
                        if not isinstance(value, list) or not value:
                            fail(
                                f"{day}/{rule_id}: not_in requires "
                                "a non-empty list value"
                            )
                    elif not isinstance(value, (int, float)):
                        fail(
                            f"{day}/{rule_id}: operator {operator!r} "
                            "requires a numeric value"
                        )

        rule_windows[day] = windows

    payload_operator = (
        semantics.get("payload_filter_definition", {}).get("operator")
    )
    observed_operators.add(payload_operator)
    if payload_operator not in supported_operators:
        fail(f"payload filter uses undeclared operator {payload_operator!r}")

    count_days = counts.get("days")
    if not isinstance(count_days, dict) or set(count_days) != EXPECTED_DAYS:
        fail("counts: pilot-day set mismatch")

    for day, values in count_days.items():
        before = values.get("rows_before_preprocessing")
        after = values.get("rows_after_preprocessing")
        label_counts = values.get("label_counts")
        category_counts = values.get("attempted_category_counts")

        if not isinstance(before, int) or not isinstance(after, int):
            fail(f"{day}: row counts must be integers")
        if before < after:
            fail(f"{day}: preprocessing increased row count")
        if not isinstance(label_counts, dict) or not label_counts:
            fail(f"{day}: missing label counts")
        if not isinstance(category_counts, dict) or not category_counts:
            fail(f"{day}: missing attempted-category counts")
        if sum(label_counts.values()) != after:
            fail(f"{day}: label counts do not sum to rows_after_preprocessing")
        if sum(category_counts.values()) != after:
            fail(
                f"{day}: attempted-category counts do not sum to "
                "rows_after_preprocessing"
            )

    anchor_entries = anchors.get("pilot_days")
    if not isinstance(anchor_entries, list):
        fail("anchors: pilot_days must be a list")

    anchor_days = {entry.get("day") for entry in anchor_entries}
    if anchor_days != EXPECTED_DAYS:
        fail("anchors: pilot-day set mismatch")

    timezone_policy = anchors.get("timezone_policy", {})
    if timezone_policy.get("source_timezone") != "UTC":
        fail("anchors: source timezone must be UTC")
    if timezone_policy.get("normalization_timezone") != "UTC":
        fail("anchors: normalization timezone must be UTC")
    if timezone_policy.get("utc_offset_seconds") != 0:
        fail("anchors: UTC offset must be zero")
    if timezone_policy.get("daylight_saving_adjustment") is not False:
        fail("anchors: daylight-saving adjustment must be false")

    for entry in anchor_entries:
        day = entry["day"]
        midnight_ns = expected_midnight_ns(day)

        if entry.get("utc_midnight_ns") != midnight_ns:
            fail(f"{day}: incorrect UTC midnight nanoseconds")
        if entry.get("utc_midnight") != iso_utc(midnight_ns):
            fail(f"{day}: incorrect UTC midnight text")

        anchor_windows = entry.get("attack_windows")
        if not isinstance(anchor_windows, list):
            fail(f"{day}: attack_windows must be a list")

        normalized_windows = []
        for window in anchor_windows:
            start_ns = window.get("start_ns")
            end_ns = window.get("end_ns")
            if window.get("start_utc") != iso_utc(start_ns):
                fail(f"{day}: start UTC text mismatch")
            if window.get("end_utc") != iso_utc(end_ns):
                fail(f"{day}: end UTC text mismatch")
            normalized_windows.append((start_ns, end_ns))

        if normalized_windows != rule_windows[day]:
            fail(f"{day}: timezone anchors do not match rule windows")

    print("CICIDS2018 freeze validation passed")
    print(f"  days: {len(EXPECTED_DAYS)}")
    print(f"  rules: {len(rule_ids)}")
    print(f"  operators: {', '.join(sorted(observed_operators))}")
    print(f"  source commit: {EXPECTED_SOURCE['commit']}")


if __name__ == "__main__":
    main()
