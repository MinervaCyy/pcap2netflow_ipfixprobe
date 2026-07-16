#!/usr/bin/env python3
"""Download one inventory-pinned CICIDS2018 archive safely."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import shutil
import subprocess
import sys
import time
import urllib.parse
from datetime import datetime, timezone
from email.utils import format_datetime, parsedate_to_datetime
from pathlib import Path
from typing import Any


SUCCESS = 0
MANUAL_REVIEW = 2
RETRY_EXHAUSTED = 3
USAGE_ERROR = 64

RETRYABLE_CURL_CODES = {
    5,   # proxy resolution
    6,   # host resolution
    7,   # connection failure
    18,  # partial file
    28,  # timeout
    35,  # TLS connection error
    52,  # empty reply
    55,  # send failure
    56,  # receive failure
    92,  # HTTP/2 stream error
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def filename_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def write_text_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(path)


def normalize_http_datetime(value: str) -> datetime:
    stripped = value.strip()

    try:
        parsed = datetime.fromisoformat(
            stripped.replace("Z", "+00:00")
        )
    except ValueError:
        parsed = parsedate_to_datetime(stripped)

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def datetime_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace(
        "+00:00",
        "Z",
    )


def parse_http_blocks(raw: str) -> list[dict[str, Any]]:
    normalized = raw.replace("\r\n", "\n")
    blocks: list[dict[str, Any]] = []

    for candidate in normalized.split("\n\n"):
        lines = [
            line
            for line in candidate.splitlines()
            if line.strip()
        ]

        if not lines or not lines[0].startswith("HTTP/"):
            continue

        status_parts = lines[0].split()
        status_code = (
            int(status_parts[1])
            if len(status_parts) >= 2
            and status_parts[1].isdigit()
            else None
        )

        headers: dict[str, list[str]] = {}

        for line in lines[1:]:
            if ":" not in line:
                continue

            name, value = line.split(":", 1)
            headers.setdefault(
                name.strip().lower(),
                [],
            ).append(value.strip())

        blocks.append(
            {
                "status_line": lines[0],
                "status_code": status_code,
                "headers": headers,
            }
        )

    return blocks


def parse_writeout(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            f"unable to parse curl write-out JSON {path}: {exc}"
        ) from exc


def final_identity_block(
    blocks: list[dict[str, Any]],
) -> dict[str, Any]:
    candidates = [
        block
        for block in blocks
        if "content-length" in block["headers"]
        and "etag" in block["headers"]
        and "last-modified" in block["headers"]
    ]

    if not candidates:
        raise RuntimeError(
            "no HTTP response block contained Content-Length, "
            "ETag and Last-Modified"
        )

    return candidates[-1]


def one_header(
    block: dict[str, Any],
    name: str,
) -> str:
    values = block["headers"].get(name.lower(), [])

    if len(values) != 1:
        raise RuntimeError(
            f"expected exactly one {name} header, "
            f"observed {len(values)}"
        )

    return values[0]


def same_object_url(actual: str, expected: str) -> bool:
    actual_parts = urllib.parse.urlsplit(actual)
    expected_parts = urllib.parse.urlsplit(expected)

    return (
        actual_parts.scheme == expected_parts.scheme
        and actual_parts.hostname == expected_parts.hostname
        and actual_parts.port == expected_parts.port
        and urllib.parse.unquote(actual_parts.path)
        == urllib.parse.unquote(expected_parts.path)
        and actual_parts.query == expected_parts.query
    )


def run_command(
    command: list[str],
    *,
    cwd: Path,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def quarantine_part(
    part_path: Path,
    reason: str,
) -> Path | None:
    if not part_path.exists():
        return None

    safe_reason = "".join(
        character
        if character.isalnum() or character in "-_"
        else "-"
        for character in reason
    ).strip("-")

    quarantine = part_path.with_name(
        f"{part_path.name}.{safe_reason}."
        f"{filename_timestamp()}.quarantine"
    )

    os.replace(part_path, quarantine)
    return quarantine


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Download one preflight-verified CICIDS2018 archive using "
            "identity revalidation, resumable .part storage, bounded "
            "retries, exact-size validation and atomic publication."
        )
    )
    parser.add_argument(
        "--verification-record",
        type=Path,
        default=Path(
            "verification/"
            "cicids2018_wednesday_download_preflight.json"
        ),
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--manifest-dir", required=True, type=Path)
    parser.add_argument("--curl-bin", default="curl")
    parser.add_argument("--max-attempts", type=int, default=5)
    parser.add_argument(
        "--initial-backoff-seconds",
        type=float,
        default=5.0,
    )
    parser.add_argument(
        "--max-backoff-seconds",
        type=float,
        default=60.0,
    )
    parser.add_argument(
        "--total-timeout-seconds",
        type=int,
        default=43200,
        help="Total transfer-session deadline; default is 12 hours.",
    )
    parser.add_argument(
        "--head-timeout-seconds",
        type=int,
        default=120,
    )
    parser.add_argument(
        "--connect-timeout-seconds",
        type=int,
        default=30,
    )
    parser.add_argument(
        "--reserve-bytes",
        type=int,
        default=10 * 1024**3,
    )
    parser.add_argument(
        "--limit-rate",
        required=True,
        help=(
            "Explicit curl transfer-rate policy, for example 100M. "
            "Use 0 to record an explicitly unlimited transfer."
        ),
    )
    parser.add_argument(
        "--speed-limit-bytes-per-second",
        type=int,
        default=1024,
    )
    parser.add_argument(
        "--speed-time-seconds",
        type=int,
        default=120,
    )
    parser.add_argument(
        "--allow-http-for-tests",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(__file__).resolve().parents[1]

    verification_path = (
        args.verification_record
        if args.verification_record.is_absolute()
        else root / args.verification_record
    ).resolve()

    output_path = (
        args.output
        if args.output.is_absolute()
        else root / args.output
    ).resolve()

    manifest_dir = (
        args.manifest_dir
        if args.manifest_dir.is_absolute()
        else root / args.manifest_dir
    ).resolve()

    part_path = output_path.with_name(output_path.name + ".part")
    sidecar_path = output_path.with_name(output_path.name + ".sha256")

    if args.max_attempts < 1:
        print("ERROR: max-attempts must be positive", file=sys.stderr)
        return USAGE_ERROR

    if args.total_timeout_seconds < 1:
        print(
            "ERROR: total-timeout-seconds must be positive",
            file=sys.stderr,
        )
        return USAGE_ERROR

    if args.head_timeout_seconds < 1:
        print(
            "ERROR: head-timeout-seconds must be positive",
            file=sys.stderr,
        )
        return USAGE_ERROR

    if args.connect_timeout_seconds < 1:
        print(
            "ERROR: connect-timeout-seconds must be positive",
            file=sys.stderr,
        )
        return USAGE_ERROR

    if args.initial_backoff_seconds < 0:
        print(
            "ERROR: initial backoff cannot be negative",
            file=sys.stderr,
        )
        return USAGE_ERROR

    if args.max_backoff_seconds < args.initial_backoff_seconds:
        print(
            "ERROR: maximum backoff is below initial backoff",
            file=sys.stderr,
        )
        return USAGE_ERROR

    if args.reserve_bytes < 0:
        print("ERROR: reserve-bytes cannot be negative", file=sys.stderr)
        return USAGE_ERROR

    if args.speed_limit_bytes_per_second < 1:
        print(
            "ERROR: speed-limit-bytes-per-second must be positive",
            file=sys.stderr,
        )
        return USAGE_ERROR

    if args.speed_time_seconds < 1:
        print(
            "ERROR: speed-time-seconds must be positive",
            file=sys.stderr,
        )
        return USAGE_ERROR

    if output_path.exists():
        print(
            f"ERROR: final output already exists: {output_path}",
            file=sys.stderr,
        )
        return USAGE_ERROR

    if sidecar_path.exists():
        print(
            f"ERROR: SHA-256 sidecar already exists: {sidecar_path}",
            file=sys.stderr,
        )
        return USAGE_ERROR

    if manifest_dir.exists() and any(manifest_dir.iterdir()):
        print(
            f"ERROR: manifest directory is not empty: {manifest_dir}",
            file=sys.stderr,
        )
        return USAGE_ERROR

    curl_path = shutil.which(args.curl_bin)

    if curl_path is None:
        print(
            f"ERROR: curl executable not found: {args.curl_bin}",
            file=sys.stderr,
        )
        return USAGE_ERROR

    try:
        verification = json.loads(
            verification_path.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        print(
            f"ERROR: unable to read verification record: {exc}",
            file=sys.stderr,
        )
        return USAGE_ERROR

    if verification.get("status") != (
        "preflight_passed_download_not_started"
    ):
        print(
            "ERROR: verification record does not authorise downloader "
            "freezing or execution",
            file=sys.stderr,
        )
        return MANUAL_REVIEW

    gates = verification.get("gates", {})

    if gates.get("dataset_download") != "not_started":
        print(
            "ERROR: verification record does not show download not_started",
            file=sys.stderr,
        )
        return MANUAL_REVIEW

    if gates.get("extraction") != "closed":
        print(
            "ERROR: extraction gate is not closed",
            file=sys.stderr,
        )
        return MANUAL_REVIEW

    if verification.get("warnings") != []:
        print(
            "ERROR: verification record contains unresolved warnings",
            file=sys.stderr,
        )
        return MANUAL_REVIEW

    selected = verification.get("selected_object", {})

    try:
        object_url = str(selected["url"])
        object_key = str(selected["key"])
        expected_size = int(selected["size_bytes"])
        expected_etag = str(selected["etag"])
        expected_last_modified = normalize_http_datetime(
            str(selected["last_modified"])
        )
    except (KeyError, TypeError, ValueError) as exc:
        print(
            f"ERROR: invalid selected-object record: {exc}",
            file=sys.stderr,
        )
        return USAGE_ERROR

    url_parts = urllib.parse.urlsplit(object_url)

    if url_parts.scheme != "https":
        if not (
            args.allow_http_for_tests
            and url_parts.scheme == "http"
        ):
            print(
                "ERROR: production downloads require HTTPS",
                file=sys.stderr,
            )
            return MANUAL_REVIEW

    output_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_dir.mkdir(parents=True, exist_ok=True)
    attempts_dir = manifest_dir / "attempts"
    attempts_dir.mkdir()

    manifest_path = manifest_dir / "download_manifest.json"

    verification_sha256 = sha256_file(verification_path)
    downloader_path = Path(__file__).resolve()
    downloader_sha256 = sha256_file(downloader_path)

    part_size_initial = (
        part_path.stat().st_size
        if part_path.exists()
        else 0
    )

    if part_size_initial > expected_size:
        quarantine = quarantine_part(
            part_path,
            "oversized-before-download",
        )
        print(
            "ERROR: existing partial file is larger than expected; "
            f"quarantined at {quarantine}",
            file=sys.stderr,
        )
        return MANUAL_REVIEW

    statvfs = os.statvfs(output_path.parent)
    available_bytes = statvfs.f_bavail * statvfs.f_frsize
    remaining_bytes = expected_size - part_size_initial
    required_bytes = remaining_bytes + args.reserve_bytes

    if available_bytes < required_bytes:
        print(
            "ERROR: insufficient free space for remaining download "
            "plus reserve",
            file=sys.stderr,
        )
        return MANUAL_REVIEW

    started_epoch = time.monotonic()
    deadline = started_epoch + args.total_timeout_seconds

    manifest: dict[str, Any] = {
        "schema_version": "1.0",
        "record_type": "cicids2018_archive_download",
        "status": "running",
        "started_at_utc": utc_now(),
        "completed_at_utc": None,
        "verification": {
            "path": str(verification_path),
            "sha256": verification_sha256,
            "source_preflight_sha256": verification.get(
                "source_preflight",
                {},
            ).get("sha256"),
            "formal_inventory_sha256": verification.get(
                "formal_inventory",
                {},
            ).get("inventory_sha256"),
        },
        "downloader": {
            "path": str(downloader_path),
            "sha256": downloader_sha256,
            "curl_path": curl_path,
        },
        "selected_object": {
            "key": object_key,
            "url": object_url,
            "expected_size_bytes": expected_size,
            "expected_etag": expected_etag,
            "expected_last_modified": datetime_z(
                expected_last_modified
            ),
        },
        "paths": {
            "final": str(output_path),
            "part": str(part_path),
            "sha256_sidecar": str(sidecar_path),
            "manifest_dir": str(manifest_dir),
        },
        "policy": {
            "max_attempts": args.max_attempts,
            "initial_backoff_seconds": (
                args.initial_backoff_seconds
            ),
            "max_backoff_seconds": args.max_backoff_seconds,
            "total_timeout_seconds": args.total_timeout_seconds,
            "head_timeout_seconds": args.head_timeout_seconds,
            "connect_timeout_seconds": (
                args.connect_timeout_seconds
            ),
            "reserve_bytes": args.reserve_bytes,
            "limit_rate": (
                "unlimited"
                if args.limit_rate == "0"
                else args.limit_rate
            ),
            "speed_limit_bytes_per_second": (
                args.speed_limit_bytes_per_second
            ),
            "speed_time_seconds": args.speed_time_seconds,
            "remote_identity_revalidated_before_every_transfer": True,
            "conditional_get_if_match": True,
            "conditional_get_if_unmodified_since": True,
            "automatic_internal_curl_retries": 0,
        },
        "capacity": {
            "part_size_initial_bytes": part_size_initial,
            "remaining_bytes": remaining_bytes,
            "reserve_bytes": args.reserve_bytes,
            "required_bytes": required_bytes,
            "available_bytes": available_bytes,
            "passed": True,
        },
        "attempts": [],
        "final": None,
        "error": None,
        "quarantined_part": None,
        "extraction_authorised": False,
    }

    write_json_atomic(manifest_path, manifest)

    def finish_manual_review(
        message: str,
        *,
        quarantine_reason: str | None = None,
    ) -> int:
        quarantine: Path | None = None

        if quarantine_reason is not None:
            quarantine = quarantine_part(
                part_path,
                quarantine_reason,
            )

        manifest["status"] = "manual_review_required"
        manifest["completed_at_utc"] = utc_now()
        manifest["error"] = message
        manifest["quarantined_part"] = (
            str(quarantine)
            if quarantine is not None
            else None
        )
        write_json_atomic(manifest_path, manifest)

        print(f"ERROR: {message}", file=sys.stderr)

        if quarantine is not None:
            print(
                f"Quarantined partial file: {quarantine}",
                file=sys.stderr,
            )

        return MANUAL_REVIEW

    def remaining_deadline_seconds() -> int:
        return max(
            0,
            math.floor(deadline - time.monotonic()),
        )

    expected_http_last_modified = format_datetime(
        expected_last_modified,
        usegmt=True,
    )

    for attempt_number in range(1, args.max_attempts + 1):
        remaining_deadline = remaining_deadline_seconds()

        if remaining_deadline <= 0:
            manifest["status"] = "total_timeout_exceeded"
            manifest["completed_at_utc"] = utc_now()
            manifest["error"] = (
                "total download-session timeout expired"
            )
            write_json_atomic(manifest_path, manifest)
            print(
                "ERROR: total download-session timeout expired",
                file=sys.stderr,
            )
            return RETRY_EXHAUSTED

        attempt_dir = attempts_dir / f"attempt_{attempt_number:03d}"
        attempt_dir.mkdir()

        attempt_record: dict[str, Any] = {
            "attempt": attempt_number,
            "started_at_utc": utc_now(),
            "completed_at_utc": None,
            "part_size_before_bytes": (
                part_path.stat().st_size
                if part_path.exists()
                else 0
            ),
            "head": None,
            "transfer": None,
            "backoff_seconds_after_attempt": None,
        }

        manifest["attempts"].append(attempt_record)
        write_json_atomic(manifest_path, manifest)

        # ----------------------------------------------------------
        # Identity revalidation before every fresh/resumed transfer.
        # ----------------------------------------------------------

        head_headers = attempt_dir / "head.headers.txt"
        head_writeout = attempt_dir / "head.writeout.json"
        head_stderr = attempt_dir / "head.stderr.txt"

        allowed_protocol = (
            "=http"
            if url_parts.scheme == "http"
            else "=https"
        )

        head_max_time = min(
            args.head_timeout_seconds,
            remaining_deadline,
        )

        head_command = [
            curl_path,
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--max-redirs",
            "0",
            "--head",
            "--proto",
            allowed_protocol,
            "--proto-redir",
            allowed_protocol,
            "--connect-timeout",
            str(args.connect_timeout_seconds),
            "--max-time",
            str(head_max_time),
            "--dump-header",
            str(head_headers),
            "--output",
            os.devnull,
            "--write-out",
            "%{json}",
            object_url,
        ]

        head_started = time.monotonic()
        head_result = run_command(head_command, cwd=root)
        head_elapsed = time.monotonic() - head_started

        head_writeout.write_bytes(head_result.stdout)
        head_stderr.write_bytes(head_result.stderr)

        head_record: dict[str, Any] = {
            "command": head_command,
            "started_at_utc": attempt_record["started_at_utc"],
            "elapsed_seconds": round(head_elapsed, 6),
            "curl_exit_code": head_result.returncode,
            "headers_path": str(
                head_headers.relative_to(manifest_dir)
            ),
            "headers_sha256": (
                sha256_file(head_headers)
                if head_headers.exists()
                else None
            ),
            "writeout_path": str(
                head_writeout.relative_to(manifest_dir)
            ),
            "writeout_sha256": sha256_file(head_writeout),
            "stderr_path": str(
                head_stderr.relative_to(manifest_dir)
            ),
            "stderr_sha256": sha256_file(head_stderr),
            "identity_matches": False,
        }
        attempt_record["head"] = head_record

        if head_result.returncode != 0:
            head_record["error"] = (
                head_result.stderr.decode(
                    errors="replace",
                ).strip()
            )

            if (
                head_result.returncode in RETRYABLE_CURL_CODES
                and attempt_number < args.max_attempts
            ):
                backoff = min(
                    args.max_backoff_seconds,
                    args.initial_backoff_seconds
                    * (2 ** (attempt_number - 1)),
                )
                backoff = min(
                    backoff,
                    max(0.0, deadline - time.monotonic()),
                )
                attempt_record[
                    "backoff_seconds_after_attempt"
                ] = backoff
                attempt_record["completed_at_utc"] = utc_now()
                write_json_atomic(manifest_path, manifest)

                if backoff > 0:
                    time.sleep(backoff)

                continue

            attempt_record["completed_at_utc"] = utc_now()
            write_json_atomic(manifest_path, manifest)

            return finish_manual_review(
                "remote identity HEAD request failed with curl "
                f"status {head_result.returncode}"
            )

        try:
            head_json = parse_writeout(head_writeout)
            head_blocks = parse_http_blocks(
                head_headers.read_text(
                    encoding="iso-8859-1",
                )
            )
            identity_block = final_identity_block(head_blocks)

            content_length = int(
                one_header(
                    identity_block,
                    "content-length",
                )
            )
            observed_etag = one_header(
                identity_block,
                "etag",
            ).strip('"')
            observed_last_modified = normalize_http_datetime(
                one_header(
                    identity_block,
                    "last-modified",
                )
            )
            accept_ranges_values = identity_block[
                "headers"
            ].get("accept-ranges", [])
            accept_ranges = (
                accept_ranges_values[-1]
                if accept_ranges_values
                else None
            )

            http_code = int(head_json.get("http_code", 0))
            effective_url = str(
                head_json.get("url_effective", "")
            )
            redirect_count = int(
                head_json.get("num_redirects", 0)
            )

            head_record.update(
                {
                    "http_code": http_code,
                    "effective_url": effective_url,
                    "redirect_count": redirect_count,
                    "content_length": content_length,
                    "etag": observed_etag,
                    "last_modified": datetime_z(
                        observed_last_modified
                    ),
                    "accept_ranges": accept_ranges,
                    "remote_ip": head_json.get("remote_ip"),
                }
            )

        except (RuntimeError, ValueError) as exc:
            attempt_record["completed_at_utc"] = utc_now()
            write_json_atomic(manifest_path, manifest)

            return finish_manual_review(
                f"unable to validate HEAD response: {exc}",
                quarantine_reason="invalid-head-response",
            )

        identity_errors: list[str] = []

        if http_code != 200:
            identity_errors.append(
                f"HEAD HTTP status {http_code} is not 200"
            )

        if redirect_count != 0:
            identity_errors.append(
                f"unexpected redirect count {redirect_count}"
            )

        if not same_object_url(effective_url, object_url):
            identity_errors.append(
                "effective URL differs from the pinned object URL"
            )

        if content_length != expected_size:
            identity_errors.append(
                "Content-Length differs from the formal inventory"
            )

        if observed_etag != expected_etag:
            identity_errors.append(
                "ETag differs from the formal inventory"
            )

        if observed_last_modified != expected_last_modified:
            identity_errors.append(
                "Last-Modified differs from the formal inventory"
            )

        if accept_ranges != "bytes":
            identity_errors.append(
                "Accept-Ranges: bytes is not advertised"
            )

        if identity_errors:
            head_record["identity_errors"] = identity_errors
            attempt_record["completed_at_utc"] = utc_now()
            write_json_atomic(manifest_path, manifest)

            return finish_manual_review(
                "; ".join(identity_errors),
                quarantine_reason="remote-identity-mismatch",
            )

        head_record["identity_matches"] = True
        write_json_atomic(manifest_path, manifest)

        # ----------------------------------------------------------
        # Transfer attempt.
        # ----------------------------------------------------------

        part_size_before = (
            part_path.stat().st_size
            if part_path.exists()
            else 0
        )

        if part_size_before > expected_size:
            attempt_record["completed_at_utc"] = utc_now()
            write_json_atomic(manifest_path, manifest)

            return finish_manual_review(
                "partial file grew beyond the expected object size",
                quarantine_reason="oversized-part",
            )

        if part_size_before == expected_size:
            transfer_record = {
                "skipped": True,
                "reason": (
                    "existing .part already has expected size after "
                    "successful remote identity revalidation"
                ),
                "part_size_before_bytes": part_size_before,
                "part_size_after_bytes": part_size_before,
            }
            attempt_record["transfer"] = transfer_record
        else:
            remaining_deadline = remaining_deadline_seconds()

            if remaining_deadline <= 0:
                manifest["status"] = "total_timeout_exceeded"
                manifest["completed_at_utc"] = utc_now()
                manifest["error"] = (
                    "total timeout expired before transfer"
                )
                write_json_atomic(manifest_path, manifest)
                return RETRY_EXHAUSTED

            get_headers = attempt_dir / "get.headers.txt"
            get_writeout = attempt_dir / "get.writeout.json"
            get_stderr = attempt_dir / "get.stderr.txt"

            get_command = [
                curl_path,
                "--fail",
                "--silent",
                "--show-error",
                "--location",
                "--max-redirs",
                "0",
                "--proto",
                allowed_protocol,
                "--proto-redir",
                allowed_protocol,
                "--connect-timeout",
                str(args.connect_timeout_seconds),
                "--max-time",
                str(remaining_deadline),
                "--speed-limit",
                str(args.speed_limit_bytes_per_second),
                "--speed-time",
                str(args.speed_time_seconds),
                "--header",
                f'If-Match: "{expected_etag}"',
                "--header",
                (
                    "If-Unmodified-Since: "
                    f"{expected_http_last_modified}"
                ),
                "--dump-header",
                str(get_headers),
                "--output",
                str(part_path),
                "--write-out",
                "%{json}",
            ]

            if args.limit_rate != "0":
                get_command.extend(
                    ["--limit-rate", args.limit_rate]
                )

            if part_size_before > 0:
                get_command.extend(["--continue-at", "-"])

            get_command.append(object_url)

            transfer_started_utc = utc_now()
            transfer_started = time.monotonic()
            get_result = run_command(get_command, cwd=root)
            transfer_elapsed = time.monotonic() - transfer_started

            get_writeout.write_bytes(get_result.stdout)
            get_stderr.write_bytes(get_result.stderr)

            part_size_after = (
                part_path.stat().st_size
                if part_path.exists()
                else 0
            )

            transfer_record = {
                "command": get_command,
                "started_at_utc": transfer_started_utc,
                "elapsed_seconds": round(
                    transfer_elapsed,
                    6,
                ),
                "curl_exit_code": get_result.returncode,
                "resumed": part_size_before > 0,
                "part_size_before_bytes": part_size_before,
                "part_size_after_bytes": part_size_after,
                "bytes_added": (
                    part_size_after - part_size_before
                ),
                "headers_path": str(
                    get_headers.relative_to(manifest_dir)
                ),
                "headers_sha256": (
                    sha256_file(get_headers)
                    if get_headers.exists()
                    else None
                ),
                "writeout_path": str(
                    get_writeout.relative_to(manifest_dir)
                ),
                "writeout_sha256": sha256_file(get_writeout),
                "stderr_path": str(
                    get_stderr.relative_to(manifest_dir)
                ),
                "stderr_sha256": sha256_file(get_stderr),
            }
            attempt_record["transfer"] = transfer_record

            get_json: dict[str, Any] = {}

            try:
                get_json = parse_writeout(get_writeout)
            except RuntimeError:
                pass

            transfer_http_code = int(
                get_json.get("http_code", 0)
            )
            transfer_effective_url = str(
                get_json.get("url_effective", "")
            )
            transfer_redirect_count = int(
                get_json.get("num_redirects", 0)
            )

            transfer_record.update(
                {
                    "http_code": transfer_http_code,
                    "effective_url": transfer_effective_url,
                    "redirect_count": transfer_redirect_count,
                    "remote_ip": get_json.get("remote_ip"),
                    "download_speed_bytes_per_second": (
                        get_json.get("speed_download")
                    ),
                }
            )

            if part_size_after > expected_size:
                attempt_record["completed_at_utc"] = utc_now()
                write_json_atomic(manifest_path, manifest)

                return finish_manual_review(
                    "transfer produced a partial file larger than "
                    "the expected object size",
                    quarantine_reason="oversized-transfer",
                )

            if transfer_effective_url and not same_object_url(
                transfer_effective_url,
                object_url,
            ):
                attempt_record["completed_at_utc"] = utc_now()
                write_json_atomic(manifest_path, manifest)

                return finish_manual_review(
                    "transfer effective URL differs from the pinned URL",
                    quarantine_reason="transfer-url-mismatch",
                )

            if transfer_redirect_count != 0:
                attempt_record["completed_at_utc"] = utc_now()
                write_json_atomic(manifest_path, manifest)

                return finish_manual_review(
                    "transfer unexpectedly followed a redirect",
                    quarantine_reason="transfer-redirect",
                )

            if part_size_before > 0:
                if get_result.returncode == 0 and (
                    transfer_http_code != 206
                ):
                    attempt_record["completed_at_utc"] = utc_now()
                    write_json_atomic(manifest_path, manifest)

                    return finish_manual_review(
                        "resumed transfer did not return HTTP 206",
                        quarantine_reason="resume-response-invalid",
                    )
            elif get_result.returncode == 0 and (
                transfer_http_code != 200
            ):
                attempt_record["completed_at_utc"] = utc_now()
                write_json_atomic(manifest_path, manifest)

                return finish_manual_review(
                    "fresh transfer did not return HTTP 200",
                    quarantine_reason="fresh-response-invalid",
                )

            if get_result.returncode != 0:
                transfer_record["stderr"] = (
                    get_result.stderr.decode(
                        errors="replace",
                    ).strip()
                )

                if transfer_http_code in {412, 416}:
                    attempt_record["completed_at_utc"] = utc_now()
                    write_json_atomic(manifest_path, manifest)

                    return finish_manual_review(
                        "conditional or range request was rejected "
                        f"with HTTP {transfer_http_code}",
                        quarantine_reason="conditional-range-rejected",
                    )

                if get_result.returncode == 33:
                    attempt_record["completed_at_utc"] = utc_now()
                    write_json_atomic(manifest_path, manifest)

                    return finish_manual_review(
                        "curl rejected resume because byte ranges were "
                        "not honoured",
                        quarantine_reason="resume-rejected",
                    )

                retryable = (
                    get_result.returncode
                    in RETRYABLE_CURL_CODES
                )

                if (
                    retryable
                    and attempt_number < args.max_attempts
                ):
                    backoff = min(
                        args.max_backoff_seconds,
                        args.initial_backoff_seconds
                        * (2 ** (attempt_number - 1)),
                    )
                    backoff = min(
                        backoff,
                        max(
                            0.0,
                            deadline - time.monotonic(),
                        ),
                    )

                    attempt_record[
                        "backoff_seconds_after_attempt"
                    ] = backoff
                    attempt_record["completed_at_utc"] = utc_now()
                    write_json_atomic(manifest_path, manifest)

                    if backoff > 0:
                        time.sleep(backoff)

                    continue

                attempt_record["completed_at_utc"] = utc_now()
                write_json_atomic(manifest_path, manifest)

                if retryable:
                    manifest["status"] = "retry_exhausted"
                    manifest["completed_at_utc"] = utc_now()
                    manifest["error"] = (
                        "bounded retry policy exhausted after "
                        f"{attempt_number} attempts"
                    )
                    write_json_atomic(manifest_path, manifest)

                    print(
                        "ERROR: bounded retry policy exhausted; "
                        f"partial file retained at {part_path}",
                        file=sys.stderr,
                    )
                    return RETRY_EXHAUSTED

                return finish_manual_review(
                    "non-retryable curl transfer failure with status "
                    f"{get_result.returncode}"
                )

        final_part_size = (
            part_path.stat().st_size
            if part_path.exists()
            else 0
        )

        attempt_record["completed_at_utc"] = utc_now()

        if final_part_size != expected_size:
            write_json_atomic(manifest_path, manifest)

            if attempt_number < args.max_attempts:
                backoff = min(
                    args.max_backoff_seconds,
                    args.initial_backoff_seconds
                    * (2 ** (attempt_number - 1)),
                )
                attempt_record[
                    "backoff_seconds_after_attempt"
                ] = backoff
                write_json_atomic(manifest_path, manifest)

                if backoff > 0:
                    time.sleep(backoff)

                continue

            manifest["status"] = "retry_exhausted"
            manifest["completed_at_utc"] = utc_now()
            manifest["error"] = (
                "transfer attempts ended without reaching the exact "
                "inventory size"
            )
            write_json_atomic(manifest_path, manifest)

            print(
                "ERROR: transfer attempts ended without reaching "
                "the exact inventory size",
                file=sys.stderr,
            )
            return RETRY_EXHAUSTED

        # ----------------------------------------------------------
        # Exact-size success: hash, atomically publish, write sidecar.
        # ----------------------------------------------------------

        hash_started_utc = utc_now()
        hash_started = time.monotonic()
        final_sha256 = sha256_file(part_path)
        hash_elapsed = time.monotonic() - hash_started

        os.replace(part_path, output_path)

        write_text_atomic(
            sidecar_path,
            f"{final_sha256}  {output_path.name}\n",
        )

        manifest["status"] = "complete"
        manifest["completed_at_utc"] = utc_now()
        manifest["final"] = {
            "path": str(output_path),
            "size_bytes": output_path.stat().st_size,
            "sha256": final_sha256,
            "sha256_sidecar": str(sidecar_path),
            "hash_started_at_utc": hash_started_utc,
            "hash_elapsed_seconds": round(
                hash_elapsed,
                6,
            ),
            "published_atomically_from_part": True,
        }
        manifest["error"] = None
        write_json_atomic(manifest_path, manifest)

        print("CICIDS2018 archive download completed")
        print(f"  key: {object_key}")
        print(f"  final path: {output_path}")
        print(f"  size bytes: {output_path.stat().st_size}")
        print(f"  SHA-256: {final_sha256}")
        print(f"  attempts: {len(manifest['attempts'])}")
        print(f"  manifest: {manifest_path}")
        print("  extraction authorised: false")
        return SUCCESS

    manifest["status"] = "retry_exhausted"
    manifest["completed_at_utc"] = utc_now()
    manifest["error"] = "attempt loop ended unexpectedly"
    write_json_atomic(manifest_path, manifest)
    return RETRY_EXHAUSTED


if __name__ == "__main__":
    raise SystemExit(main())
