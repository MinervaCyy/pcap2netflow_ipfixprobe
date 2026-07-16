#!/usr/bin/env python3
"""Collect a frozen, read-only CICIDS2018 S3 formal inventory."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


S3_NAMESPACE = {
    "s3": "http://s3.amazonaws.com/doc/2006-03-01/"
}

ROLE = "frozen_formal_inventory"
SCHEMA_VERSION = "1.0"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def write_bytes_atomic(path: Path, value: bytes) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(value)
    temporary.replace(path)


def write_text_atomic(path: Path, value: str) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(value, encoding="utf-8")
    temporary.replace(path)


def parse_list_page(xml_body: bytes) -> dict[str, Any]:
    root = ET.fromstring(xml_body)
    entries = root.findall("s3:Contents", S3_NAMESPACE)

    key_count_text = root.findtext(
        "s3:KeyCount",
        default="",
        namespaces=S3_NAMESPACE,
    )

    if not key_count_text.isdigit():
        raise ValueError("missing or invalid S3 KeyCount")

    key_count = int(key_count_text)

    if key_count != len(entries):
        raise ValueError(
            f"S3 KeyCount mismatch: {key_count} != {len(entries)}"
        )

    objects: list[dict[str, Any]] = []

    for entry in entries:
        key = entry.findtext(
            "s3:Key",
            default="",
            namespaces=S3_NAMESPACE,
        )
        size_text = entry.findtext(
            "s3:Size",
            default="",
            namespaces=S3_NAMESPACE,
        )

        if not size_text.isdigit():
            raise ValueError(f"invalid S3 Size for key {key!r}")

        objects.append(
            {
                "key": key,
                "size_bytes": int(size_text),
                "etag": entry.findtext(
                    "s3:ETag",
                    default="",
                    namespaces=S3_NAMESPACE,
                ).strip('"'),
                "last_modified": entry.findtext(
                    "s3:LastModified",
                    default="",
                    namespaces=S3_NAMESPACE,
                ),
            }
        )

    is_truncated = (
        root.findtext(
            "s3:IsTruncated",
            default="false",
            namespaces=S3_NAMESPACE,
        ).lower()
        == "true"
    )

    next_token = root.findtext(
        "s3:NextContinuationToken",
        default="",
        namespaces=S3_NAMESPACE,
    )

    if is_truncated and not next_token:
        raise ValueError(
            "truncated S3 response lacks NextContinuationToken"
        )

    return {
        "key_count": key_count,
        "objects": objects,
        "is_truncated": is_truncated,
        "next_continuation_token": (
            next_token if is_truncated else None
        ),
    }


def classify_object(
    prefix: str,
    key: str,
    size_bytes: int,
    selection: dict[str, Any],
) -> dict[str, Any]:
    if not key.startswith(prefix):
        return {
            "decision": "unexpected",
            "reason": "key is outside the exact day prefix",
            "basename": key.rstrip("/").rsplit("/", 1)[-1],
            "direct_child": False,
            "directory_marker": False,
        }

    relative = key[len(prefix):]
    basename = relative.rstrip("/").rsplit("/", 1)[-1]

    directory_marker = (
        relative == ""
        and key.endswith("/")
        and size_bytes == 0
    )

    if directory_marker:
        return {
            "decision": "ignored_directory_marker",
            "reason": "zero-byte day-prefix directory marker",
            "basename": basename,
            "direct_child": False,
            "directory_marker": True,
        }

    direct_child = (
        relative != ""
        and "/" not in relative.rstrip("/")
    )

    if not direct_child:
        return {
            "decision": "unexpected",
            "reason": "nested objects are forbidden by policy",
            "basename": basename,
            "direct_child": False,
            "directory_marker": False,
        }

    selected_basename = selection["selected_basename_exact"]
    excluded = set(selection["explicitly_excluded_basenames"])

    if basename == selected_basename:
        if size_bytes <= 0:
            return {
                "decision": "unexpected",
                "reason": "selected archive is empty",
                "basename": basename,
                "direct_child": True,
                "directory_marker": False,
            }

        return {
            "decision": "selected",
            "reason": "exact direct-child pcap.zip selector match",
            "basename": basename,
            "direct_child": True,
            "directory_marker": False,
        }

    if basename in excluded:
        return {
            "decision": "excluded",
            "reason": "explicitly excluded logs archive",
            "basename": basename,
            "direct_child": True,
            "directory_marker": False,
        }

    return {
        "decision": "unexpected",
        "reason": "unrecognized direct-child non-marker object",
        "basename": basename,
        "direct_child": True,
        "directory_marker": False,
    }


def run_command(
    command: list[str],
    cwd: Path,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def git_value(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(arguments)} failed: "
            f"{result.stderr.strip()}"
        )

    return result.stdout.strip()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Collect the frozen formal ListObjectsV2 inventory for all "
            "CICIDS2018 pilot days. This command never downloads S3 objects."
        )
    )
    parser.add_argument(
        "--policy",
        type=Path,
        default=Path("configs/cicids2018_acquisition_policy.yaml"),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--curl-bin",
        default="curl",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(__file__).resolve().parents[1]

    policy_path = (
        args.policy
        if args.policy.is_absolute()
        else root / args.policy
    ).resolve()

    output_dir = (
        args.output_dir
        if args.output_dir.is_absolute()
        else root / args.output_dir
    ).resolve()

    if output_dir.exists():
        print(
            f"ERROR: output directory already exists: {output_dir}",
            file=sys.stderr,
        )
        return 64

    policy = json.loads(
        policy_path.read_text(encoding="utf-8")
    )

    if policy.get("schema_version") != "1.1":
        print(
            "ERROR: acquisition policy schema_version must be 1.1",
            file=sys.stderr,
        )
        return 2

    scope = policy["scope"]

    if (
        scope.get("formal_inventory_and_download_status")
        != "not_started"
    ):
        print(
            "ERROR: policy no longer permits initial formal inventory",
            file=sys.stderr,
        )
        return 2

    selection = policy["selection"]

    if (
        selection.get("object_scope")
        != "direct_children_of_exact_day_prefix"
        or selection.get("selected_basename_exact") != "pcap.zip"
        or selection.get("selected_object_count_per_day") != 1
        or selection.get("explicitly_excluded_basenames")
        != ["logs.zip"]
        or selection.get("nested_objects_allowed") is not False
    ):
        print(
            "ERROR: unsupported or unfrozen selection policy",
            file=sys.stderr,
        )
        return 2

    output_dir.mkdir(parents=True)
    raw_dir = output_dir / "raw_xml"
    raw_dir.mkdir()

    curl_version_result = subprocess.run(
        [args.curl_bin, "--version"],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )

    if curl_version_result.returncode != 0:
        print(
            f"ERROR: curl --version failed: "
            f"{curl_version_result.stderr.strip()}",
            file=sys.stderr,
        )
        return 2

    curl_version_lines = curl_version_result.stdout.splitlines()

    if not curl_version_lines:
        print("ERROR: curl returned no version output", file=sys.stderr)
        return 2

    curl_version = curl_version_lines[0]
    endpoint = policy["source"]["endpoint"]
    prefix_template = policy["source"]["day_prefix_template"]
    pilot_days = scope["pilot_days"]

    started_at = utc_now()
    day_reports: list[dict[str, Any]] = []

    try:
        for day in pilot_days:
            prefix = prefix_template.format(day=day)
            continuation_token: str | None = None
            page_number = 0
            parsed_total = 0
            day_objects: list[dict[str, Any]] = []
            requests: list[dict[str, Any]] = []

            while True:
                page_number += 1

                parameters = {
                    "list-type": "2",
                    "prefix": prefix,
                    "max-keys": "1000",
                }

                if continuation_token is not None:
                    parameters["continuation-token"] = (
                        continuation_token
                    )

                request_url = (
                    endpoint
                    + "?"
                    + urllib.parse.urlencode(parameters)
                )

                command = [
                    args.curl_bin,
                    "--fail",
                    "--silent",
                    "--show-error",
                    "--location",
                    "--retry",
                    "5",
                    "--retry-delay",
                    "5",
                    "--connect-timeout",
                    "30",
                    "--max-time",
                    "120",
                    request_url,
                ]

                request_started = utc_now()
                result = run_command(command, root)
                request_completed = utc_now()

                safe_day = day.replace("/", "_")
                xml_path = raw_dir / (
                    f"{safe_day}_page_{page_number:03d}.xml"
                )
                stderr_path = raw_dir / (
                    f"{safe_day}_page_{page_number:03d}.stderr.txt"
                )

                write_bytes_atomic(xml_path, result.stdout)
                write_bytes_atomic(stderr_path, result.stderr)

                if result.returncode != 0:
                    raise RuntimeError(
                        f"{day} page {page_number}: curl failed with "
                        f"status {result.returncode}: "
                        f"{result.stderr.decode(errors='replace').strip()}"
                    )

                page = parse_list_page(result.stdout)
                parsed_total += len(page["objects"])

                for obj in page["objects"]:
                    classification = classify_object(
                        prefix,
                        obj["key"],
                        obj["size_bytes"],
                        selection,
                    )
                    obj.update(classification)
                    day_objects.append(obj)

                requests.append(
                    {
                        "page": page_number,
                        "endpoint": endpoint,
                        "query_parameters": parameters,
                        "request_url": request_url,
                        "requested_at_utc": request_started,
                        "completed_at_utc": request_completed,
                        "http_client": "curl",
                        "http_client_version": curl_version,
                        "curl_exit_code": result.returncode,
                        "key_count": page["key_count"],
                        "parsed_contents_count": len(
                            page["objects"]
                        ),
                        "counts_equal": (
                            page["key_count"]
                            == len(page["objects"])
                        ),
                        "is_truncated": page["is_truncated"],
                        "raw_xml_path": str(
                            xml_path.relative_to(output_dir)
                        ),
                        "raw_xml_sha256": sha256_file(xml_path),
                        "stderr_path": str(
                            stderr_path.relative_to(output_dir)
                        ),
                    }
                )

                if not page["is_truncated"]:
                    break

                continuation_token = page[
                    "next_continuation_token"
                ]

            selected = [
                obj
                for obj in day_objects
                if obj["decision"] == "selected"
            ]
            excluded = [
                obj
                for obj in day_objects
                if obj["decision"] == "excluded"
            ]
            unexpected = [
                obj
                for obj in day_objects
                if obj["decision"] == "unexpected"
            ]
            markers = [
                obj
                for obj in day_objects
                if obj["decision"] == "ignored_directory_marker"
            ]
            actual = [
                obj
                for obj in day_objects
                if not obj["directory_marker"]
            ]

            if parsed_total != len(day_objects):
                raise RuntimeError(
                    f"{day}: cumulative parsed object mismatch"
                )

            if len(selected) != 1:
                raise RuntimeError(
                    f"{day}: expected exactly one selected pcap.zip, "
                    f"observed {len(selected)}"
                )

            if unexpected:
                keys = [obj["key"] for obj in unexpected]
                raise RuntimeError(
                    f"{day}: unexpected non-marker objects: {keys}"
                )

            if len(markers) != 1:
                raise RuntimeError(
                    f"{day}: expected one directory marker, "
                    f"observed {len(markers)}"
                )

            day_reports.append(
                {
                    "day": day,
                    "prefix": prefix,
                    "request_count": len(requests),
                    "requests": requests,
                    "raw_listed_entry_count": len(day_objects),
                    "directory_marker_count": len(markers),
                    "listed_object_count": len(actual),
                    "listed_total_size_bytes": sum(
                        obj["size_bytes"] for obj in actual
                    ),
                    "selected_object_count": len(selected),
                    "selected_total_size_bytes": sum(
                        obj["size_bytes"] for obj in selected
                    ),
                    "excluded_object_count": len(excluded),
                    "excluded_total_size_bytes": sum(
                        obj["size_bytes"] for obj in excluded
                    ),
                    "unexpected_non_marker_object_count": len(
                        unexpected
                    ),
                    "objects": day_objects,
                }
            )

    except Exception as exc:
        failure = {
            "schema_version": SCHEMA_VERSION,
            "role": ROLE,
            "status": "failed",
            "formal_inventory_eligible": False,
            "object_downloads_performed": 0,
            "error": str(exc),
            "started_at_utc": started_at,
            "failed_at_utc": utc_now(),
        }

        write_text_atomic(
            output_dir / "inventory.failed.json",
            json.dumps(
                failure,
                indent=2,
                sort_keys=True,
            )
            + "\n",
        )

        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    policy_hash = sha256_file(policy_path)
    script_path = Path(__file__).resolve()

    report = {
        "schema_version": SCHEMA_VERSION,
        "role": ROLE,
        "status": "complete",
        "formal_inventory_eligible": True,
        "object_downloads_performed": 0,
        "started_at_utc": started_at,
        "completed_at_utc": utc_now(),
        "repository": {
            "commit": git_value(root, "rev-parse", "HEAD"),
            "branch": git_value(
                root,
                "rev-parse",
                "--abbrev-ref",
                "HEAD",
            ),
            "worktree_clean": (
                git_value(root, "status", "--porcelain") == ""
            ),
        },
        "policy": {
            "path": str(policy_path.relative_to(root)),
            "schema_version": policy["schema_version"],
            "sha256": policy_hash,
        },
        "collector": {
            "path": str(script_path.relative_to(root)),
            "sha256": sha256_file(script_path),
            "python_version": platform.python_version(),
            "xml_parser": "xml.etree.ElementTree",
            "http_client": "curl",
            "http_client_version": curl_version,
        },
        "selection": selection,
        "days": day_reports,
        "totals": {
            "pilot_day_count": len(day_reports),
            "request_count": sum(
                day["request_count"] for day in day_reports
            ),
            "listed_object_count": sum(
                day["listed_object_count"] for day in day_reports
            ),
            "listed_total_size_bytes": sum(
                day["listed_total_size_bytes"]
                for day in day_reports
            ),
            "selected_object_count": sum(
                day["selected_object_count"]
                for day in day_reports
            ),
            "selected_total_size_bytes": sum(
                day["selected_total_size_bytes"]
                for day in day_reports
            ),
            "unexpected_non_marker_object_count": sum(
                day["unexpected_non_marker_object_count"]
                for day in day_reports
            ),
        },
    }

    inventory_bytes = (
        json.dumps(
            report,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")

    inventory_path = output_dir / "inventory.json"
    write_bytes_atomic(inventory_path, inventory_bytes)

    digest = sha256_bytes(inventory_bytes)
    write_text_atomic(
        output_dir / "inventory.sha256",
        f"{digest}  inventory.json\n",
    )

    print("CICIDS2018 formal inventory completed")
    print(f"  role: {ROLE}")
    print("  formal inventory eligible: true")
    print("  object downloads performed: 0")
    print(f"  pilot days: {len(day_reports)}")
    print(f"  requests: {report['totals']['request_count']}")
    print(
        "  listed objects: "
        f"{report['totals']['listed_object_count']}"
    )
    print(
        "  selected objects: "
        f"{report['totals']['selected_object_count']}"
    )
    print(
        "  selected bytes: "
        f"{report['totals']['selected_total_size_bytes']:,}"
    )
    print(
        "  unexpected objects: "
        f"{report['totals']['unexpected_non_marker_object_count']}"
    )
    print(f"  inventory: {inventory_path}")
    print(f"  inventory SHA-256: {digest}")

    for day in day_reports:
        selected = next(
            obj
            for obj in day["objects"]
            if obj["decision"] == "selected"
        )
        print(
            f"  {day['day']}: "
            f"{selected['size_bytes']:,} bytes, "
            f"ETag={selected['etag']}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
