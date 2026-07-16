#!/usr/bin/env python3
"""Run pcapfix on an isolated copy and select repaired or original output."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


NO_REPAIR_MARKER = "Your pcap file looks proper. Nothing to fix!"
MANUAL_REVIEW_EXIT_CODE = 2
USAGE_EXIT_CODE = 64


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def resolve_executable(value: str) -> Path:
    if "/" in value:
        candidate = Path(value).expanduser().resolve()
        if not candidate.is_file() or not os.access(candidate, os.X_OK):
            raise ValueError(
                f"pcapfix executable is not usable: {candidate}"
            )
        return candidate

    discovered = shutil.which(value)
    if discovered is None:
        raise ValueError(f"pcapfix executable was not found: {value}")

    return Path(discovered).resolve()


def write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run pcapfix -d on an isolated working copy and select either "
            "the repaired artifact or the unchanged working copy."
        )
    )
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument(
        "--pcapfix-bin",
        default="pcapfix",
        help="pcapfix executable name or path",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    input_path = args.input.expanduser().resolve()
    work_dir = args.work_dir.expanduser().resolve()
    output_path = args.output.expanduser().resolve()
    manifest_path = args.manifest.expanduser().resolve()

    if not input_path.is_file():
        print(f"ERROR: input is not a file: {input_path}", file=sys.stderr)
        return USAGE_EXIT_CODE

    if output_path == input_path:
        print(
            "ERROR: output must differ from the immutable input",
            file=sys.stderr,
        )
        return USAGE_EXIT_CODE

    if output_path.exists():
        print(
            f"ERROR: selected output already exists: {output_path}",
            file=sys.stderr,
        )
        return USAGE_EXIT_CODE

    if manifest_path.exists():
        print(
            f"ERROR: manifest already exists: {manifest_path}",
            file=sys.stderr,
        )
        return USAGE_EXIT_CODE

    if work_dir.exists() and any(work_dir.iterdir()):
        print(
            f"ERROR: work directory is not empty: {work_dir}",
            file=sys.stderr,
        )
        return USAGE_EXIT_CODE

    try:
        pcapfix_bin = resolve_executable(args.pcapfix_bin)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return USAGE_EXIT_CODE

    work_dir.mkdir(parents=True, exist_ok=True)

    working_copy = work_dir / "input.pcap"
    repaired_artifact = work_dir / "repaired.pcap"
    stdout_path = work_dir / "pcapfix.stdout.txt"
    stderr_path = work_dir / "pcapfix.stderr.txt"

    source_hash_before = sha256_file(input_path)
    shutil.copy2(input_path, working_copy)
    working_hash_before = sha256_file(working_copy)

    command = [
        str(pcapfix_bin),
        "-d",
        "-o",
        repaired_artifact.name,
        working_copy.name,
    ]

    started = time.perf_counter()
    result = subprocess.run(
        command,
        cwd=work_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    elapsed_seconds = time.perf_counter() - started

    stdout_path.write_text(result.stdout, encoding="utf-8")
    stderr_path.write_text(result.stderr, encoding="utf-8")

    source_hash_after = sha256_file(input_path)
    working_hash_after = sha256_file(working_copy)

    source_unchanged = source_hash_before == source_hash_after
    working_copy_unchanged = (
        working_hash_before == working_hash_after
    )

    repaired_exists = repaired_artifact.is_file()
    repaired_size = (
        repaired_artifact.stat().st_size
        if repaired_exists
        else None
    )
    repaired_nonempty = (
        repaired_exists
        and repaired_size is not None
        and repaired_size > 0
    )

    combined_output = result.stdout + "\n" + result.stderr
    no_repair_marker_seen = NO_REPAIR_MARKER in combined_output

    decision = "fail_for_manual_review"
    touched: bool | None = None
    selected_source: Path | None = None
    reason = ""

    if not source_unchanged:
        reason = "immutable source input changed unexpectedly"
    elif not working_copy_unchanged:
        reason = "pcapfix modified the working input copy in place"
    elif result.returncode == 0 and repaired_nonempty:
        decision = "use_repaired_artifact"
        touched = True
        selected_source = repaired_artifact
        reason = "successful pcapfix run produced a repaired artifact"
    elif (
        result.returncode == 0
        and not repaired_exists
        and no_repair_marker_seen
    ):
        decision = "use_original_no_repair_needed"
        touched = False
        selected_source = working_copy
        reason = (
            "successful pcapfix run produced no repaired artifact and "
            "reported that the input required no repair"
        )
    elif result.returncode != 0:
        reason = (
            f"pcapfix exited with non-zero status {result.returncode}"
        )
    elif repaired_exists and not repaired_nonempty:
        reason = "pcapfix produced an empty repaired artifact"
    else:
        reason = (
            "successful pcapfix run produced neither a usable repaired "
            "artifact nor the pinned no-repair marker"
        )

    selected_hash: str | None = None

    if selected_source is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(selected_source, output_path)
        selected_hash = sha256_file(output_path)

    manifest: dict[str, Any] = {
        "schema_version": "1.0",
        "status": (
            "selected"
            if selected_source is not None
            else "manual_review_required"
        ),
        "decision": decision,
        "reason": reason,
        "touched": touched,
        "input": {
            "path": str(input_path),
            "sha256_before": source_hash_before,
            "sha256_after": source_hash_after,
            "unchanged": source_unchanged,
        },
        "working_copy": {
            "path": str(working_copy),
            "sha256_before": working_hash_before,
            "sha256_after": working_hash_after,
            "unchanged": working_copy_unchanged,
        },
        "pcapfix": {
            "executable": str(pcapfix_bin),
            "argv": command,
            "exit_code": result.returncode,
            "elapsed_seconds": round(elapsed_seconds, 6),
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "no_repair_marker": NO_REPAIR_MARKER,
            "no_repair_marker_seen": no_repair_marker_seen,
        },
        "repaired_artifact": {
            "path": str(repaired_artifact),
            "exists": repaired_exists,
            "size_bytes": repaired_size,
            "sha256": (
                sha256_file(repaired_artifact)
                if repaired_nonempty
                else None
            ),
        },
        "selected_output": {
            "path": (
                str(output_path)
                if selected_source is not None
                else None
            ),
            "source_path": (
                str(selected_source)
                if selected_source is not None
                else None
            ),
            "sha256": selected_hash,
        },
    }

    write_json_atomic(manifest_path, manifest)

    print("pcapfix selection result")
    print(f"  decision: {decision}")
    print(f"  pcapfix exit code: {result.returncode}")
    print(f"  repaired artifact exists: {repaired_exists}")
    print(f"  no-repair marker seen: {no_repair_marker_seen}")
    print(f"  touched: {touched}")
    print(f"  manifest: {manifest_path}")

    if selected_source is None:
        print(f"ERROR: {reason}", file=sys.stderr)
        return MANUAL_REVIEW_EXIT_CODE

    print(f"  selected output: {output_path}")
    print(f"  selected SHA-256: {selected_hash}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
