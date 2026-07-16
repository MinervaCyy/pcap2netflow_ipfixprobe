#!/usr/bin/env python3
"""Validate the frozen CICIDS2018 acquisition policy and tool pin."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "configs/cicids2018_acquisition_policy.yaml"
VERSIONS_PATH = ROOT / "docker/versions.env"
COUNTS_PATH = ROOT / "tests/expected/cicids2018_pilot_counts.json"
PLATFORM_PATH = ROOT / "verification/platform.md"

EXPECTED_DAYS = [
    "Wednesday-14-02-2018",
    "Thursday-15-02-2018",
    "Thursday-22-02-2018",
]

EXPECTED_ORDER = [
    "capinfos_pre",
    "pcapfix_attempt",
    "select_repaired_or_original",
    "reordercap",
    "mergecap",
    "capinfos_post",
]


def fail(message: str) -> None:
    raise SystemExit(f"ERROR: {message}")


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail(f"missing file: {path.relative_to(ROOT)}")
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON-compatible YAML in {path.name}: {exc}")

    if not isinstance(value, dict):
        fail(f"{path.name}: top level must be an object")

    return value


def read_env(name: str) -> str:
    text = VERSIONS_PATH.read_text(encoding="utf-8")
    match = re.search(
        rf'(?m)^{re.escape(name)}=(?:"([^"]*)"|\'([^\']*)\'|([^\n]*))$',
        text,
    )

    if not match:
        fail(f"missing {name} in docker/versions.env")

    return next(
        value for value in match.groups()
        if value is not None
    ).strip()


def installed_pcapfix_version() -> str:
    try:
        return subprocess.check_output(
            ["dpkg-query", "-W", "-f=${Version}", "pcapfix"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (FileNotFoundError, subprocess.CalledProcessError):
        fail("pcapfix is not installed")


def require_true(value: Any, message: str) -> None:
    if value is not True:
        fail(message)


def main() -> None:
    policy = load_json(POLICY_PATH)
    counts = load_json(COUNTS_PATH)

    if policy.get("schema_version") != "1.0":
        fail("unsupported acquisition-policy schema version")

    scope = policy.get("scope", {})
    if scope.get("pilot_days") != EXPECTED_DAYS:
        fail("pilot-day set or order mismatch")

    if scope.get("formal_inventory_and_download_status") != "not_started":
        fail("formal inventory must remain not_started at policy freeze")

    source = policy.get("source", {})
    if source.get("bucket") != "cse-cic-ids2018":
        fail("S3 bucket mismatch")
    if source.get("region") != "ca-central-1":
        fail("S3 region mismatch")
    require_true(
        source.get("anonymous_access"),
        "S3 access must be anonymous",
    )

    reconnaissance = policy.get("reconnaissance", {})
    if (
        reconnaissance.get("request_role")
        != "reconnaissance_not_frozen_inventory"
    ):
        fail("reconnaissance role is ambiguous")
    require_true(
        reconnaissance.get("read_only_list_request_only"),
        "reconnaissance must be list-only",
    )
    if reconnaissance.get("object_download_allowed") is not False:
        fail("reconnaissance must not download objects")
    require_true(
        reconnaissance.get(
            "formal_inventory_must_be_repeated_after_reconnaissance"
        ),
        "formal inventory must be repeated after reconnaissance",
    )

    selection = policy.get("selection", {})
    require_true(
        selection.get("required_day_prefix_match"),
        "exact day-prefix matching must be required",
    )
    if not selection.get("pcap_subtree_component_regex"):
        fail("missing PCAP-subtree selector")
    if (
        selection.get("unexpected_object_type_action")
        != "fail_for_manual_review"
    ):
        fail("unexpected object types must fail for review")

    inventory = policy.get("formal_inventory", {})
    require_true(
        inventory.get("performed_before_download"),
        "formal inventory must precede download",
    )
    require_true(
        inventory.get("inventory_sha256_required"),
        "formal inventory SHA-256 must be required",
    )
    require_true(
        inventory.get("pagination", {}).get(
            "follow_continuation_tokens_until_complete"
        ),
        "S3 pagination must run to completion",
    )

    integrity = policy.get("integrity", {})
    require_true(
        integrity.get("etag", {}).get("must_not_be_assumed_md5"),
        "ETag must not be treated as MD5",
    )
    if (
        integrity.get("sha256", {}).get("role")
        != "primary_local_integrity_evidence"
    ):
        fail("SHA-256 must be primary integrity evidence")

    processing = policy.get("pcap_processing", {})
    if processing.get("required_order") != EXPECTED_ORDER:
        fail("PCAP processing order mismatch")

    pcapfix = processing.get("pcapfix", {})
    if pcapfix.get("mode") != "-d":
        fail("pcapfix mode must be -d")
    require_true(
        pcapfix.get("unconditional_attempt"),
        "pcapfix must be attempted for every input",
    )
    require_true(
        pcapfix.get("record_elapsed_seconds_per_file"),
        "pcapfix elapsed time must be recorded per file",
    )

    selection_branch = processing.get(
        "pcapfix_output_selection",
        {},
    )
    require_true(
        selection_branch.get(
            "must_not_assume_every_input_produces_output"
        ),
        "pcapfix no-output branch is not frozen",
    )
    if (
        selection_branch.get("otherwise")
        != "fail_for_manual_review"
    ):
        fail("ambiguous pcapfix results must fail")

    reordercap = processing.get("reordercap", {})
    require_true(
        reordercap.get("run_for_every_selected_pcap"),
        "reordercap must run for every selected PCAP",
    )
    require_true(
        reordercap.get("unconditional"),
        "reordercap must be unconditional",
    )

    require_true(
        processing.get("capinfos_post", {}).get(
            "strict_time_order_must_be_true"
        ),
        "final strict time order must be required",
    )

    rare = policy.get("rare_class_validation", {})
    if rare.get("count_comparison_role") != "diagnostic_not_exact_acceptance":
        fail("rare-class counts must not be exact acceptance criteria")
    if rare.get("final_arbiter") != "4V_packet_and_flow_trace":
        fail("4V must be the rare-class final arbiter")

    sql = rare.get("sql_full_trace", {})
    if sql.get("reference_total") != 20:
        fail("SQL full-trace reference total must be 20")
    if "sampling is not permitted" not in sql.get("trace_scope", ""):
        fail("SQL validation must prohibit sampling")

    semantics = counts.get("comparison_semantics", {})
    if semantics.get("mode") != "diagnostic_not_exact_acceptance":
        fail("expected-count comparison semantics are missing")
    if semantics.get("final_arbiter") != "4V_packet_and_flow_trace":
        fail("expected-count fixture does not declare 4V final arbitration")

    sql_fixture = semantics.get("thursday_22_sql_full_trace", {})
    if sql_fixture.get("reference_total") != 20:
        fail("expected-count SQL reference total mismatch")
    if sql_fixture.get("sampling_allowed") is not False:
        fail("expected-count SQL tracing must prohibit sampling")

    expected_version = read_env("PCAPFIX_VERSION")
    installed_version = installed_pcapfix_version()

    if pcapfix.get("package_version") != expected_version:
        fail("policy and versions.env pcapfix versions differ")
    if installed_version != expected_version:
        fail(
            "installed and pinned pcapfix versions differ: "
            f"{installed_version!r} != {expected_version!r}"
        )

    platform_text = PLATFORM_PATH.read_text(encoding="utf-8")
    if "https://ports.ubuntu.com/ubuntu-ports/" not in platform_text:
        fail("platform document lacks the HTTPS Ubuntu ports source")
    if "outbound HTTP" not in platform_text:
        fail("platform document lacks the outbound HTTP diagnosis")

    serialized = json.dumps(policy)
    if "PENDING" in serialized:
        fail("policy still contains PENDING values")

    print("CICIDS2018 acquisition policy validation passed")
    print(f"  pilot days: {len(EXPECTED_DAYS)}")
    print(f"  processing order: {' -> '.join(EXPECTED_ORDER)}")
    print(f"  pcapfix version: {installed_version}")
    print("  reconnaissance: list-only, not formal inventory")
    print("  count comparison: diagnostic")
    print("  SQL validation: full 20-flow reference trace")
    print("  ETag role: auxiliary")
    print("  SHA-256 role: primary")


if __name__ == "__main__":
    main()
