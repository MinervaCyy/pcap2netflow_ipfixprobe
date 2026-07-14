#!/usr/bin/env python3
"""Validate IPFIXcol2 JSONL flow records against the project contract."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Any


class ContractError(ValueError):
    """Raised when a schema or flow record violates the project contract."""


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}

    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON object key: {key}")
        result[key] = value

    return result


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ContractError) as exc:
        raise ContractError(f"cannot load schema {path}: {exc}") from exc

    if not isinstance(value, dict):
        raise ContractError("schema root must be a JSON object")

    return value


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ContractError(f"cannot read input {path}: {exc}") from exc

    records: list[dict[str, Any]] = []

    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue

        try:
            value = json.loads(
                line,
                object_pairs_hook=reject_duplicate_keys,
            )
        except (json.JSONDecodeError, ContractError) as exc:
            raise ContractError(
                f"line {line_number}: invalid JSON: {exc}"
            ) from exc

        if not isinstance(value, dict):
            raise ContractError(
                f"line {line_number}: each JSONL entry must be an object"
            )

        records.append(value)

    if not records:
        raise ContractError("input contains no JSON flow records")

    return records


def require_schema_contract(schema: dict[str, Any]) -> None:
    expected = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:pcap2netflow:ipfixcol2-biflow:v1",
        "type": "object",
        "additionalProperties": True,
    }

    for key, expected_value in expected.items():
        if schema.get(key) != expected_value:
            raise ContractError(
                f"schema field {key!r} must equal {expected_value!r}"
            )

    required = schema.get("required")
    properties = schema.get("properties")
    metadata = schema.get("x-pcap2netflow")

    if not isinstance(required, list) or not required:
        raise ContractError("schema required field list is missing or empty")

    if len(required) != len(set(required)):
        raise ContractError("schema required field list contains duplicates")

    if not isinstance(properties, dict) or not properties:
        raise ContractError("schema properties object is missing or empty")

    missing_definitions = sorted(set(required) - properties.keys())

    if missing_definitions:
        raise ContractError(
            "required fields lack property definitions: "
            + ", ".join(missing_definitions)
        )

    if not isinstance(metadata, dict):
        raise ContractError("schema x-pcap2netflow metadata is missing")

    expected_metadata = {
        "contract_version": "1.0.0",
        "numeric_names": False,
        "split_biflow": False,
        "timestamp_serialization": "unix",
        "timestamp_value_unit": "milliseconds",
        "additional_information_elements_allowed": True,
    }

    for key, expected_value in expected_metadata.items():
        if metadata.get(key) != expected_value:
            raise ContractError(
                f"schema metadata {key!r} must equal {expected_value!r}"
            )


def validate_type(
    field_name: str,
    value: Any,
    definition: dict[str, Any],
    record_number: int,
) -> None:
    expected_type = definition.get("type")

    if expected_type == "integer":
        valid = isinstance(value, int) and not isinstance(value, bool)
    elif expected_type == "string":
        valid = isinstance(value, str)
    elif expected_type is None:
        valid = True
    else:
        raise ContractError(
            f"unsupported schema type for field {field_name}: "
            f"{expected_type!r}"
        )

    if not valid:
        raise ContractError(
            f"record {record_number}: field {field_name!r} must be "
            f"{expected_type}"
        )


def validate_constraints(
    field_name: str,
    value: Any,
    definition: dict[str, Any],
    record_number: int,
) -> None:
    if "const" in definition and value != definition["const"]:
        raise ContractError(
            f"record {record_number}: field {field_name!r} must equal "
            f"{definition['const']!r}"
        )

    if "enum" in definition and value not in definition["enum"]:
        raise ContractError(
            f"record {record_number}: field {field_name!r} is outside "
            f"the allowed values {definition['enum']!r}"
        )

    if "minimum" in definition and value < definition["minimum"]:
        raise ContractError(
            f"record {record_number}: field {field_name!r} is below "
            f"minimum {definition['minimum']}"
        )

    if "maximum" in definition and value > definition["maximum"]:
        raise ContractError(
            f"record {record_number}: field {field_name!r} exceeds "
            f"maximum {definition['maximum']}"
        )

    pattern = definition.get("pattern")

    if pattern is not None:
        if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
            raise ContractError(
                f"record {record_number}: field {field_name!r} does not "
                "match its required pattern"
            )

    value_format = definition.get("format")

    if value_format in {"ipv4", "ipv6"}:
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ContractError(
                f"record {record_number}: field {field_name!r} is not "
                f"a valid {value_format} address"
            ) from exc

        expected_version = 4 if value_format == "ipv4" else 6

        if parsed.version != expected_version:
            raise ContractError(
                f"record {record_number}: field {field_name!r} is not "
                f"an IPv{expected_version} address"
            )


def validate_ip_address_family(
    record: dict[str, Any],
    record_number: int,
) -> None:
    ip_version = record["iana:ipVersion"]

    if ip_version == 4:
        required_addresses = (
            "iana:sourceIPv4Address",
            "iana:destinationIPv4Address",
        )
        forbidden_addresses = (
            "iana:sourceIPv6Address",
            "iana:destinationIPv6Address",
        )
    elif ip_version == 6:
        required_addresses = (
            "iana:sourceIPv6Address",
            "iana:destinationIPv6Address",
        )
        forbidden_addresses = (
            "iana:sourceIPv4Address",
            "iana:destinationIPv4Address",
        )
    else:
        raise ContractError(
            f"record {record_number}: unsupported IP version {ip_version!r}"
        )

    missing = [
        field_name
        for field_name in required_addresses
        if field_name not in record
    ]

    if missing:
        raise ContractError(
            f"record {record_number}: missing IP address fields: "
            + ", ".join(missing)
        )

    conflicting = [
        field_name
        for field_name in forbidden_addresses
        if field_name in record
    ]

    if conflicting:
        raise ContractError(
            f"record {record_number}: conflicting IP address fields: "
            + ", ".join(conflicting)
        )


def validate_semantics(
    record: dict[str, Any],
    record_number: int,
) -> None:
    start = record["iana:flowStartMicroseconds"]
    end = record["iana:flowEndMicroseconds"]

    if end < start:
        raise ContractError(
            f"record {record_number}: flow end timestamp precedes start"
        )


def validate_records(
    records: list[dict[str, Any]],
    schema: dict[str, Any],
) -> set[str]:
    required = set(schema["required"])
    properties: dict[str, dict[str, Any]] = schema["properties"]
    observed_fields: set[str] = set()

    for record_number, record in enumerate(records, start=1):
        observed_fields.update(record)

        missing = sorted(required - record.keys())

        if missing:
            raise ContractError(
                f"record {record_number}: missing required fields: "
                + ", ".join(missing)
            )

        for field_name, value in record.items():
            definition = properties.get(field_name)

            if definition is None:
                continue

            validate_type(
                field_name,
                value,
                definition,
                record_number,
            )
            validate_constraints(
                field_name,
                value,
                definition,
                record_number,
            )

        validate_ip_address_family(record, record_number)
        validate_semantics(record, record_number)

    return observed_fields


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)

    return digest.hexdigest()


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate IPFIXcol2 JSONL flow records against the "
            "pcap2netflow biflow contract."
        )
    )
    parser.add_argument(
        "--schema",
        type=Path,
        required=True,
        help="Path to the versioned JSON schema contract.",
    )
    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Path to the JSON Lines flow file.",
    )
    parser.add_argument(
        "--expect-records",
        type=int,
        help="Require an exact flow-record count.",
    )
    parser.add_argument(
        "--expect-sha256",
        help="Require an exact SHA-256 digest of the input file.",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()

    try:
        schema = load_json(arguments.schema)
        require_schema_contract(schema)

        records = load_jsonl(arguments.input)

        if (
            arguments.expect_records is not None
            and len(records) != arguments.expect_records
        ):
            raise ContractError(
                f"expected {arguments.expect_records} records, "
                f"found {len(records)}"
            )

        input_hash = sha256_file(arguments.input)

        if (
            arguments.expect_sha256 is not None
            and input_hash.lower() != arguments.expect_sha256.lower()
        ):
            raise ContractError(
                "input SHA-256 mismatch: "
                f"expected {arguments.expect_sha256.lower()}, "
                f"found {input_hash}"
            )

        observed_fields = validate_records(records, schema)
        declared_fields = set(schema["properties"])
        undeclared_fields = sorted(observed_fields - declared_fields)
        metadata = schema["x-pcap2netflow"]

    except ContractError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print("IPFIX JSON contract validation passed")
    print(f"schema={arguments.schema}")
    print(f"contract_version={metadata['contract_version']}")
    print(f"input={arguments.input}")
    print(f"records={len(records)}")
    print(f"sha256={input_hash}")
    print(f"observed_fields={len(observed_fields)}")
    print(
        "undeclared_fields="
        + (",".join(undeclared_fields) if undeclared_fields else "none")
    )
    print("timestamp_unit=unix_milliseconds")
    print("split_biflow=false")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
