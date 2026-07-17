#!/usr/bin/env python3
"""Clean and merge one CICIDS2018 day under the frozen Stage 2 policy."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


POLICY_SCHEMA_VERSION = "1.1"
MANIFEST_SCHEMA_VERSION = "1.0"

REQUIRED_ORDER = [
    "capinfos_pre",
    "pcapfix_attempt",
    "select_repaired_or_original",
    "reordercap",
    "mergecap",
    "capinfos_post",
]

MANUAL_REVIEW_EXIT_CODE = 2
USAGE_EXIT_CODE = 64

CAPINFOS_COLUMNS = [
    "File name",
    "Number of packets",
    "File size (bytes)",
    "Capture duration (seconds)",
    "Start time",
    "End time",
    "Strict time order",
]

# Observed with capinfos (Wireshark) 4.2.2. The pre-repair
# exception is intentionally limited to this diagnostic family.
CAPINFOS_CUT_SHORT_DIAGNOSTIC_SUBSTRING = (
    "cut short in the middle of a packet"
)

CAPINFOS_CUT_SHORT_ALLOWED_STDERR_PATTERNS = [
    re.compile(
        r'^capinfos: An error occurred after reading '
        r'\d+ packets? from ".+"\.$'
    ),
    re.compile(
        r'^capinfos: The file ".+" appears to have been cut short '
        r'in the middle of a packet\.$'
    ),
    re.compile(
        r'^\(will continue anyway, checksums might be incorrect\)$'
    ),
]


class Stage2Error(RuntimeError):
    """A processing failure with an explicit process exit code."""

    def __init__(self, message: str, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


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


def resolve_executable(value: str, role: str) -> Path:
    if "/" in value:
        candidate = Path(value).expanduser().resolve()

        if not candidate.is_file() or not os.access(candidate, os.X_OK):
            raise Stage2Error(
                f"{role} executable is not usable: {candidate}",
                USAGE_EXIT_CODE,
            )

        return candidate

    discovered = shutil.which(value)

    if discovered is None:
        raise Stage2Error(
            f"{role} executable was not found: {value}",
            USAGE_EXIT_CODE,
        )

    return Path(discovered).resolve()


def git_head(root: Path) -> str | None:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        return None

    return result.stdout.strip()


def safe_component(value: str) -> str:
    component = re.sub(r"[^A-Za-z0-9._-]+", "_", value)
    component = component.strip("._-")
    return component or "input"


def run_logged(
    command: list[str],
    *,
    cwd: Path,
    stdout_path: Path,
    stderr_path: Path,
) -> tuple[subprocess.CompletedProcess[str], float]:
    started = time.perf_counter()

    result = subprocess.run(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        check=False,
    )

    elapsed_seconds = time.perf_counter() - started

    write_text_atomic(stdout_path, result.stdout)
    write_text_atomic(stderr_path, result.stderr)

    return result, elapsed_seconds


def command_evidence(
    *,
    command: list[str],
    result: subprocess.CompletedProcess[str],
    elapsed_seconds: float,
    stdout_path: Path,
    stderr_path: Path,
) -> dict[str, Any]:
    return {
        "argv": command,
        "exit_code": result.returncode,
        "elapsed_seconds": round(elapsed_seconds, 6),
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "stdout_sha256": sha256_file(stdout_path),
        "stderr_sha256": sha256_file(stderr_path),
    }


def capture_tool_version(
    *,
    executable: Path,
    arguments: list[str],
    role: str,
    output_dir: Path,
) -> dict[str, Any]:
    stdout_path = output_dir / f"{role}.version.stdout.txt"
    stderr_path = output_dir / f"{role}.version.stderr.txt"
    command = [str(executable), *arguments]

    result, elapsed_seconds = run_logged(
        command,
        cwd=output_dir,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
    )

    combined = (result.stdout + "\n" + result.stderr).strip()

    return {
        **command_evidence(
            command=command,
            result=result,
            elapsed_seconds=elapsed_seconds,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
        ),
        "combined_output": combined,
    }


def parse_capinfos_table(stdout: str) -> dict[str, Any]:
    rows = [
        row
        for row in csv.reader(
            io.StringIO(stdout),
            delimiter="\t",
            quotechar='"',
        )
        if row
    ]

    if len(rows) != 2:
        raise Stage2Error(
            "capinfos table output must contain exactly one header "
            "and one data row"
        )

    header = rows[0]
    values = rows[1]

    if len(header) != len(values):
        raise Stage2Error(
            "capinfos table header and data column counts differ"
        )

    table = dict(zip(header, values, strict=True))

    missing = [
        column
        for column in CAPINFOS_COLUMNS
        if column not in table
    ]

    if missing:
        raise Stage2Error(
            "capinfos table is missing required columns: "
            + ", ".join(missing)
        )

    try:
        packet_count = int(table["Number of packets"])
        file_size_bytes = int(table["File size (bytes)"])
        float(table["Capture duration (seconds)"])
        float(table["Start time"])
        float(table["End time"])
    except ValueError as exc:
        raise Stage2Error(
            f"capinfos returned an invalid numeric field: {exc}"
        ) from exc

    order_text = table["Strict time order"]

    if order_text not in {"True", "False"}:
        raise Stage2Error(
            "capinfos returned an invalid strict-time-order value: "
            f"{order_text!r}"
        )

    return {
        "reported_file_name": table["File name"],
        "packet_count": packet_count,
        "file_size_bytes": file_size_bytes,
        "capture_duration_seconds": table[
            "Capture duration (seconds)"
        ],
        "first_packet_time_unix_seconds": table["Start time"],
        "last_packet_time_unix_seconds": table["End time"],
        "strict_time_order": order_text == "True",
    }


def capinfos_cut_short_diagnostic_only(stderr: str) -> bool:
    """Return true only for the pinned cut-short diagnostic family."""

    lines = [
        line.strip()
        for line in stderr.splitlines()
        if line.strip()
    ]

    if len(lines) != len(
        CAPINFOS_CUT_SHORT_ALLOWED_STDERR_PATTERNS
    ):
        return False

    if (
        CAPINFOS_CUT_SHORT_DIAGNOSTIC_SUBSTRING
        not in stderr.lower()
    ):
        return False

    return all(
        pattern.fullmatch(line) is not None
        for pattern, line in zip(
            CAPINFOS_CUT_SHORT_ALLOWED_STDERR_PATTERNS,
            lines,
            strict=True,
        )
    )


def run_capinfos(
    *,
    executable: Path,
    input_path: Path,
    log_dir: Path,
    prefix: str,
    allow_cut_short_precheck: bool = False,
) -> dict[str, Any]:
    log_dir.mkdir(parents=True, exist_ok=True)

    stdout_path = log_dir / f"{prefix}.stdout.txt"
    stderr_path = log_dir / f"{prefix}.stderr.txt"
    summary_path = log_dir / f"{prefix}.summary.json"

    command = [
        str(executable),
        "-T",
        "-B",
        "-Q",
        "-c",
        "-s",
        "-a",
        "-e",
        "-u",
        "-o",
        "-S",
        str(input_path),
    ]

    result, elapsed_seconds = run_logged(
        command,
        cwd=log_dir,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
    )

    evidence = command_evidence(
        command=command,
        result=result,
        elapsed_seconds=elapsed_seconds,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
    )

    accepted_cut_short_precheck = (
        allow_cut_short_precheck
        and result.returncode == 1
        and capinfos_cut_short_diagnostic_only(result.stderr)
    )

    if result.returncode != 0 and not accepted_cut_short_precheck:
        raise Stage2Error(
            f"capinfos failed for {input_path} with exit code "
            f"{result.returncode}"
        )

    summary = parse_capinfos_table(result.stdout)

    if summary["file_size_bytes"] != input_path.stat().st_size:
        raise Stage2Error(
            "capinfos file-size report differs from the filesystem "
            f"for {input_path}"
        )

    summary_record = {
        **summary,
        "capinfos_exit_code": result.returncode,
        "accepted_cut_short_precheck": (
            accepted_cut_short_precheck
        ),
        "diagnostic_warning": (
            "input capture is cut short in the middle of a packet"
            if accepted_cut_short_precheck
            else None
        ),
    }

    write_json_atomic(summary_path, summary_record)

    return {
        "command": evidence,
        "summary": summary_record,
        "summary_path": str(summary_path),
        "summary_sha256": sha256_file(summary_path),
    }


def load_policy(path: Path) -> dict[str, Any]:
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise Stage2Error(
            f"unable to read acquisition policy: {exc}",
            USAGE_EXIT_CODE,
        ) from exc

    if policy.get("schema_version") != POLICY_SCHEMA_VERSION:
        raise Stage2Error(
            "acquisition policy schema_version must be "
            f"{POLICY_SCHEMA_VERSION}",
            USAGE_EXIT_CODE,
        )

    processing = policy.get("pcap_processing")

    if not isinstance(processing, dict):
        raise Stage2Error(
            "acquisition policy lacks pcap_processing",
            USAGE_EXIT_CODE,
        )

    if processing.get("required_order") != REQUIRED_ORDER:
        raise Stage2Error(
            "acquisition policy required_order differs from the "
            "frozen Stage 2 order",
            USAGE_EXIT_CODE,
        )

    if (
        processing.get("pcapfix", {}).get(
            "operate_only_on_isolated_working_copy"
        )
        is not True
    ):
        raise Stage2Error(
            "policy does not require isolated pcapfix working copies",
            USAGE_EXIT_CODE,
        )

    if (
        processing.get("capinfos_post", {}).get(
            "strict_time_order_must_be_true"
        )
        is not True
    ):
        raise Stage2Error(
            "policy does not require strict final time order",
            USAGE_EXIT_CODE,
        )

    return policy


def load_inputs_manifest(
    *,
    path: Path,
    day: str,
) -> list[dict[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise Stage2Error(
            f"unable to read inputs manifest: {exc}",
            USAGE_EXIT_CODE,
        ) from exc

    if payload.get("schema_version") != "1.0":
        raise Stage2Error(
            "inputs manifest schema_version must be 1.0",
            USAGE_EXIT_CODE,
        )

    if payload.get("day") != day:
        raise Stage2Error(
            "inputs manifest day does not match --day",
            USAGE_EXIT_CODE,
        )

    files = payload.get("files")

    if not isinstance(files, list) or not files:
        raise Stage2Error(
            "inputs manifest must contain a non-empty files list",
            USAGE_EXIT_CODE,
        )

    resolved: list[dict[str, Any]] = []
    source_keys: set[str] = set()
    input_paths: set[Path] = set()

    for index, item in enumerate(files):
        if not isinstance(item, dict):
            raise Stage2Error(
                f"inputs manifest file entry {index} is not an object",
                USAGE_EXIT_CODE,
            )

        source_key = item.get("source_key")
        path_text = item.get("path")

        if not isinstance(source_key, str) or not source_key:
            raise Stage2Error(
                f"inputs manifest file entry {index} has no source_key",
                USAGE_EXIT_CODE,
            )

        if not isinstance(path_text, str) or not path_text:
            raise Stage2Error(
                f"inputs manifest file entry {index} has no path",
                USAGE_EXIT_CODE,
            )

        if source_key in source_keys:
            raise Stage2Error(
                f"duplicate source_key in inputs manifest: {source_key}",
                USAGE_EXIT_CODE,
            )

        raw_path = Path(path_text).expanduser()

        input_path = (
            raw_path.resolve()
            if raw_path.is_absolute()
            else (path.parent / raw_path).resolve()
        )

        if input_path in input_paths:
            raise Stage2Error(
                f"duplicate input path in inputs manifest: {input_path}",
                USAGE_EXIT_CODE,
            )

        if not input_path.is_file():
            raise Stage2Error(
                f"input PCAP is not a file: {input_path}",
                USAGE_EXIT_CODE,
            )

        if input_path.stat().st_size <= 0:
            raise Stage2Error(
                f"input PCAP is empty: {input_path}",
                USAGE_EXIT_CODE,
            )

        source_keys.add(source_key)
        input_paths.add(input_path)

        resolved.append(
            {
                "source_key": source_key,
                "declared_path": path_text,
                "input_path": input_path,
            }
        )

    return sorted(resolved, key=lambda item: item["source_key"])


def ensure_empty_directory(path: Path, role: str) -> None:
    if path.exists() and not path.is_dir():
        raise Stage2Error(
            f"{role} path exists but is not a directory: {path}",
            USAGE_EXIT_CODE,
        )

    if path.exists() and any(path.iterdir()):
        raise Stage2Error(
            f"{role} directory is not empty: {path}",
            USAGE_EXIT_CODE,
        )

    path.mkdir(parents=True, exist_ok=True)


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]

    parser = argparse.ArgumentParser(
        description=(
            "Run the frozen CICIDS2018 Stage 2 order for one day: "
            "capinfos_pre, pcapfix selection, reordercap, mergecap, "
            "and capinfos_post with strict-time-order enforcement."
        )
    )

    parser.add_argument("--day", required=True)
    parser.add_argument(
        "--inputs-manifest",
        required=True,
        type=Path,
    )
    parser.add_argument(
        "--policy",
        type=Path,
        default=root / "configs" / "cicids2018_acquisition_policy.yaml",
    )
    parser.add_argument(
        "--selector-script",
        type=Path,
        default=root / "scripts" / "06_pcapfix_select.py",
    )
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--clean-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)

    parser.add_argument("--capinfos-bin", default="capinfos")
    parser.add_argument("--pcapfix-bin", default="pcapfix")
    parser.add_argument("--reordercap-bin", default="reordercap")
    parser.add_argument("--mergecap-bin", default="mergecap")

    return parser.parse_args()


def run_stage2(args: argparse.Namespace) -> int:
    root = Path(__file__).resolve().parents[1]

    day = args.day
    policy_path = args.policy.expanduser().resolve()
    inputs_manifest_path = args.inputs_manifest.expanduser().resolve()
    selector_script = args.selector_script.expanduser().resolve()

    work_dir = args.work_dir.expanduser().resolve()
    clean_dir = args.clean_dir.expanduser().resolve()
    output_path = args.output.expanduser().resolve()
    manifest_path = args.manifest.expanduser().resolve()

    if not selector_script.is_file():
        raise Stage2Error(
            f"pcapfix selector script is missing: {selector_script}",
            USAGE_EXIT_CODE,
        )

    if manifest_path.exists():
        raise Stage2Error(
            f"day manifest already exists: {manifest_path}",
            USAGE_EXIT_CODE,
        )

    if output_path.exists():
        raise Stage2Error(
            f"final merged output already exists: {output_path}",
            USAGE_EXIT_CODE,
        )

    candidate_path = output_path.with_name(
        output_path.name + ".stage2-candidate"
    )

    if candidate_path.exists():
        raise Stage2Error(
            f"merged candidate already exists: {candidate_path}",
            USAGE_EXIT_CODE,
        )

    policy = load_policy(policy_path)
    inputs = load_inputs_manifest(
        path=inputs_manifest_path,
        day=day,
    )

    capinfos_bin = resolve_executable(
        args.capinfos_bin,
        "capinfos",
    )
    pcapfix_bin = resolve_executable(
        args.pcapfix_bin,
        "pcapfix",
    )
    reordercap_bin = resolve_executable(
        args.reordercap_bin,
        "reordercap",
    )
    mergecap_bin = resolve_executable(
        args.mergecap_bin,
        "mergecap",
    )

    ensure_empty_directory(work_dir, "work")
    ensure_empty_directory(clean_dir, "clean")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)

    version_dir = work_dir / "tool_versions"
    version_dir.mkdir(parents=True, exist_ok=True)

    tool_versions = {
        "capinfos": capture_tool_version(
            executable=capinfos_bin,
            arguments=["--version"],
            role="capinfos",
            output_dir=version_dir,
        ),
        "pcapfix": capture_tool_version(
            executable=pcapfix_bin,
            arguments=[],
            role="pcapfix",
            output_dir=version_dir,
        ),
        "reordercap": capture_tool_version(
            executable=reordercap_bin,
            arguments=["--version"],
            role="reordercap",
            output_dir=version_dir,
        ),
        "mergecap": capture_tool_version(
            executable=mergecap_bin,
            arguments=["--version"],
            role="mergecap",
            output_dir=version_dir,
        ),
    }

    manifest: dict[str, Any] = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "record_type": "cicids2018_stage2_clean_day",
        "status": "running",
        "started_at_utc": utc_now(),
        "completed_at_utc": None,
        "day": day,
        "repository_commit": git_head(root),
        "policy": {
            "path": str(policy_path),
            "schema_version": policy["schema_version"],
            "sha256": sha256_file(policy_path),
            "required_order": REQUIRED_ORDER,
        },
        "inputs_manifest": {
            "path": str(inputs_manifest_path),
            "sha256": sha256_file(inputs_manifest_path),
            "declared_file_count": len(inputs),
        },
        "selector": {
            "path": str(selector_script),
            "sha256": sha256_file(selector_script),
            "python_executable": sys.executable,
        },
        "tools": {
            "capinfos": {
                "executable": str(capinfos_bin),
                "version_probe": tool_versions["capinfos"],
            },
            "pcapfix": {
                "executable": str(pcapfix_bin),
                "policy_package_version": policy[
                    "pcap_processing"
                ]["pcapfix"]["package_version"],
                "version_probe": tool_versions["pcapfix"],
            },
            "reordercap": {
                "executable": str(reordercap_bin),
                "version_probe": tool_versions["reordercap"],
            },
            "mergecap": {
                "executable": str(mergecap_bin),
                "version_probe": tool_versions["mergecap"],
            },
        },
        "paths": {
            "work_dir": str(work_dir),
            "clean_dir": str(clean_dir),
            "merged_candidate": str(candidate_path),
            "final_output": str(output_path),
        },
        "deterministic_input_order": [
            item["source_key"]
            for item in inputs
        ],
        "files": [],
        "counts": {
            "input_files": len(inputs),
            "touched": 0,
            "untouched": 0,
            "cut_short_inputs": 0,
        },
        "mergecap": None,
        "capinfos_post": None,
        "final_output": None,
        "error": None,
        "archive_inspection_authorised": False,
        "extraction_authorised": False,
    }

    write_json_atomic(manifest_path, manifest)

    try:
        reordered_paths: list[Path] = []

        for index, item in enumerate(inputs):
            source_key = item["source_key"]
            input_path: Path = item["input_path"]

            base_name = safe_component(Path(source_key).name)
            file_id = f"{index:04d}_{base_name}"

            file_work_dir = work_dir / "files" / file_id
            file_work_dir.mkdir(parents=True, exist_ok=False)

            input_hash_before = sha256_file(input_path)

            file_record: dict[str, Any] = {
                "index": index,
                "source_key": source_key,
                "declared_path": item["declared_path"],
                "input_path": str(input_path),
                "input_size_bytes": input_path.stat().st_size,
                "input_sha256_before": input_hash_before,
                "input_sha256_after": None,
                "input_unchanged": None,
                "status": "running",
                "touched": None,
                "capinfos_pre": None,
                "pcapfix_selection": None,
                "reordercap": None,
            }

            manifest["files"].append(file_record)
            write_json_atomic(manifest_path, manifest)

            capinfos_pre = run_capinfos(
                executable=capinfos_bin,
                input_path=input_path,
                log_dir=file_work_dir / "capinfos_pre",
                prefix="capinfos_pre",
                allow_cut_short_precheck=True,
            )

            file_record["capinfos_pre"] = capinfos_pre

            if capinfos_pre["summary"][
                "accepted_cut_short_precheck"
            ]:
                manifest["counts"]["cut_short_inputs"] += 1

            write_json_atomic(manifest_path, manifest)

            selector_work_dir = file_work_dir / "pcapfix"
            selected_path = file_work_dir / "selected.pcap"
            selector_manifest_path = (
                file_work_dir / "pcapfix_selection.json"
            )
            selector_stdout_path = (
                file_work_dir / "selector.stdout.txt"
            )
            selector_stderr_path = (
                file_work_dir / "selector.stderr.txt"
            )

            selector_command = [
                sys.executable,
                str(selector_script),
                "--input",
                str(input_path),
                "--work-dir",
                str(selector_work_dir),
                "--output",
                str(selected_path),
                "--manifest",
                str(selector_manifest_path),
                "--pcapfix-bin",
                str(pcapfix_bin),
            ]

            selector_result, selector_elapsed = run_logged(
                selector_command,
                cwd=root,
                stdout_path=selector_stdout_path,
                stderr_path=selector_stderr_path,
            )

            selector_invocation = command_evidence(
                command=selector_command,
                result=selector_result,
                elapsed_seconds=selector_elapsed,
                stdout_path=selector_stdout_path,
                stderr_path=selector_stderr_path,
            )

            selector_manifest: dict[str, Any] | None = None

            if selector_manifest_path.is_file():
                selector_manifest = json.loads(
                    selector_manifest_path.read_text(
                        encoding="utf-8"
                    )
                )

            file_record["pcapfix_selection"] = {
                "invocation": selector_invocation,
                "manifest_path": str(selector_manifest_path),
                "manifest_sha256": (
                    sha256_file(selector_manifest_path)
                    if selector_manifest_path.is_file()
                    else None
                ),
                "manifest": selector_manifest,
            }

            if selector_result.returncode != 0:
                file_record["status"] = "manual_review_required"
                write_json_atomic(manifest_path, manifest)

                raise Stage2Error(
                    "pcapfix selection failed for "
                    f"{source_key} with exit code "
                    f"{selector_result.returncode}",
                    MANUAL_REVIEW_EXIT_CODE,
                )

            if selector_manifest is None:
                raise Stage2Error(
                    f"pcapfix selector produced no manifest for {source_key}"
                )

            if selector_manifest.get("status") != "selected":
                raise Stage2Error(
                    "pcapfix selector did not report selected status for "
                    f"{source_key}",
                    MANUAL_REVIEW_EXIT_CODE,
                )

            decision = selector_manifest.get("decision")

            if decision not in {
                "use_repaired_artifact",
                "use_original_no_repair_needed",
            }:
                raise Stage2Error(
                    "pcapfix selector returned an unexpected decision for "
                    f"{source_key}: {decision!r}",
                    MANUAL_REVIEW_EXIT_CODE,
                )

            touched = selector_manifest.get("touched")

            if not isinstance(touched, bool):
                raise Stage2Error(
                    "pcapfix selector did not return a Boolean touched "
                    f"value for {source_key}",
                    MANUAL_REVIEW_EXIT_CODE,
                )

            if not selected_path.is_file():
                raise Stage2Error(
                    f"selected PCAP is missing for {source_key}"
                )

            selected_hash = sha256_file(selected_path)
            declared_selected_hash = selector_manifest.get(
                "selected_output",
                {},
            ).get("sha256")

            if selected_hash != declared_selected_hash:
                raise Stage2Error(
                    "selected PCAP SHA-256 differs from the selector "
                    f"manifest for {source_key}"
                )

            reordered_path = clean_dir / (
                f"{index:04d}_{base_name}.reordered.pcap"
            )

            reorder_dir = file_work_dir / "reordercap"
            reorder_dir.mkdir(parents=True, exist_ok=False)

            reorder_stdout = reorder_dir / "reordercap.stdout.txt"
            reorder_stderr = reorder_dir / "reordercap.stderr.txt"

            reorder_command = [
                str(reordercap_bin),
                str(selected_path),
                str(reordered_path),
            ]

            reorder_result, reorder_elapsed = run_logged(
                reorder_command,
                cwd=reorder_dir,
                stdout_path=reorder_stdout,
                stderr_path=reorder_stderr,
            )

            reorder_evidence = command_evidence(
                command=reorder_command,
                result=reorder_result,
                elapsed_seconds=reorder_elapsed,
                stdout_path=reorder_stdout,
                stderr_path=reorder_stderr,
            )

            if reorder_result.returncode != 0:
                raise Stage2Error(
                    f"reordercap failed for {source_key} with exit code "
                    f"{reorder_result.returncode}"
                )

            if not reordered_path.is_file():
                raise Stage2Error(
                    f"reordercap produced no output for {source_key}"
                )

            if reordered_path.stat().st_size <= 0:
                raise Stage2Error(
                    f"reordercap produced an empty output for {source_key}"
                )

            input_hash_after = sha256_file(input_path)
            input_unchanged = input_hash_after == input_hash_before

            if not input_unchanged:
                raise Stage2Error(
                    f"immutable input changed during processing: {input_path}"
                )

            reordered_hash = sha256_file(reordered_path)

            file_record["input_sha256_after"] = input_hash_after
            file_record["input_unchanged"] = input_unchanged
            file_record["touched"] = touched
            file_record["reordercap"] = {
                "command": reorder_evidence,
                "input_path": str(selected_path),
                "input_size_bytes": selected_path.stat().st_size,
                "input_sha256": selected_hash,
                "output_path": str(reordered_path),
                "output_size_bytes": reordered_path.stat().st_size,
                "output_sha256": reordered_hash,
            }
            file_record["status"] = "normalized"

            if touched:
                manifest["counts"]["touched"] += 1
            else:
                manifest["counts"]["untouched"] += 1

            reordered_paths.append(reordered_path)
            write_json_atomic(manifest_path, manifest)

        merge_dir = work_dir / "mergecap"
        merge_dir.mkdir(parents=True, exist_ok=False)

        merge_stdout = merge_dir / "mergecap.stdout.txt"
        merge_stderr = merge_dir / "mergecap.stderr.txt"

        merge_command = [
            str(mergecap_bin),
            "-F",
            "pcap",
            "-w",
            str(candidate_path),
            *[
                str(path)
                for path in reordered_paths
            ],
        ]

        merge_result, merge_elapsed = run_logged(
            merge_command,
            cwd=merge_dir,
            stdout_path=merge_stdout,
            stderr_path=merge_stderr,
        )

        merge_evidence = command_evidence(
            command=merge_command,
            result=merge_result,
            elapsed_seconds=merge_elapsed,
            stdout_path=merge_stdout,
            stderr_path=merge_stderr,
        )

        manifest["mergecap"] = {
            "command": merge_evidence,
            "input_order": [
                {
                    "source_key": item["source_key"],
                    "reordered_path": str(reordered_paths[index]),
                    "sha256": sha256_file(reordered_paths[index]),
                }
                for index, item in enumerate(inputs)
            ],
            "output_format": "pcap",
            "candidate_path": str(candidate_path),
            "candidate_size_bytes": (
                candidate_path.stat().st_size
                if candidate_path.is_file()
                else None
            ),
            "candidate_sha256": (
                sha256_file(candidate_path)
                if candidate_path.is_file()
                else None
            ),
            "published": False,
        }
        write_json_atomic(manifest_path, manifest)

        if merge_result.returncode != 0:
            raise Stage2Error(
                "mergecap failed with exit code "
                f"{merge_result.returncode}"
            )

        if not candidate_path.is_file():
            raise Stage2Error(
                "mergecap produced no merged candidate"
            )

        if candidate_path.stat().st_size <= 0:
            raise Stage2Error(
                "mergecap produced an empty merged candidate"
            )

        capinfos_post = run_capinfos(
            executable=capinfos_bin,
            input_path=candidate_path,
            log_dir=work_dir / "capinfos_post",
            prefix="capinfos_post",
        )

        manifest["capinfos_post"] = capinfos_post
        write_json_atomic(manifest_path, manifest)

        if not capinfos_post["summary"]["strict_time_order"]:
            raise Stage2Error(
                "final merged candidate is not in strict time order"
            )

        final_hash = sha256_file(candidate_path)
        final_size = candidate_path.stat().st_size

        os.replace(candidate_path, output_path)

        if sha256_file(output_path) != final_hash:
            raise Stage2Error(
                "final output SHA-256 changed during publication"
            )

        manifest["mergecap"]["published"] = True
        manifest["mergecap"]["published_path"] = str(output_path)
        manifest["final_output"] = {
            "path": str(output_path),
            "size_bytes": final_size,
            "sha256": final_hash,
            "strict_time_order": True,
            "published_atomically_from_candidate": True,
        }
        manifest["status"] = "complete"
        manifest["completed_at_utc"] = utc_now()
        write_json_atomic(manifest_path, manifest)

        print("CICIDS2018 Stage 2 day processing complete")
        print(f"  day: {day}")
        print(f"  input files: {len(inputs)}")
        print(f"  touched: {manifest['counts']['touched']}")
        print(f"  untouched: {manifest['counts']['untouched']}")
        print(f"  final output: {output_path}")
        print(f"  final size bytes: {final_size}")
        print(f"  final SHA-256: {final_hash}")
        print("  strict time order: true")
        print(f"  manifest: {manifest_path}")
        return 0

    except Stage2Error as exc:
        manifest["status"] = (
            "manual_review_required"
            if exc.exit_code == MANUAL_REVIEW_EXIT_CODE
            else "failed"
        )
        manifest["completed_at_utc"] = utc_now()
        manifest["error"] = {
            "type": type(exc).__name__,
            "message": str(exc),
            "exit_code": exc.exit_code,
        }
        write_json_atomic(manifest_path, manifest)

        print(f"ERROR: {exc}", file=sys.stderr)
        print(f"  manifest: {manifest_path}", file=sys.stderr)
        return exc.exit_code

    except Exception as exc:
        manifest["status"] = "failed"
        manifest["completed_at_utc"] = utc_now()
        manifest["error"] = {
            "type": type(exc).__name__,
            "message": str(exc),
            "exit_code": 1,
        }
        write_json_atomic(manifest_path, manifest)

        print(
            f"ERROR: unexpected Stage 2 failure: {exc}",
            file=sys.stderr,
        )
        print(f"  manifest: {manifest_path}", file=sys.stderr)
        return 1


def main() -> int:
    args = parse_args()

    try:
        return run_stage2(args)
    except Stage2Error as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return exc.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
