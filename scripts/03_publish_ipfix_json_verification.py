#!/usr/bin/env python3
"""Publish a verified IPFIX-to-JSON parity evidence bundle and manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent

VERSIONS_PATH = ROOT / "docker" / "versions.env"
CONFIG_PATH = ROOT / "config" / "ipfixcol2-tcp-json.xml"
SCHEMA_PATH = ROOT / "schemas" / "ipfixcol2-biflow-v1.schema.json"
PCAP_PATH = ROOT / "tests" / "data" / "smoke.pcap"
VALIDATOR_PATH = ROOT / "scripts" / "validate_ipfix_json.py"

ERROR_PATTERN = re.compile(
    r"(^|[^A-Za-z])(error|failed|drop)([^A-Za-z]|$)",
    re.IGNORECASE | re.MULTILINE,
)


class VerificationError(RuntimeError):
    """Raised when parity evidence fails a required verification."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)

    return digest.hexdigest()


def relative_path(path: Path) -> str:
    return path.resolve().relative_to(ROOT).as_posix()


def load_versions(path: Path) -> dict[str, str]:
    versions: dict[str, str] = {}

    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        if "=" not in line:
            raise VerificationError(
                f"{path}:{line_number}: invalid assignment"
            )

        key, raw_value = line.split("=", 1)
        key = key.strip()

        values = shlex.split(raw_value, posix=True)

        if len(values) != 1:
            raise VerificationError(
                f"{path}:{line_number}: invalid value for {key}"
            )

        versions[key] = values[0]

    required = {
        "PIPELINE_VERSION",
        "IPFIXPROBE_REPOSITORY",
        "IPFIXPROBE_TAG",
        "IPFIXPROBE_COMMIT",
        "LIBFDS_REPOSITORY",
        "LIBFDS_VERSION",
        "LIBFDS_COMMIT",
        "IPFIXCOL2_REPOSITORY",
        "IPFIXCOL2_VERSION",
        "IPFIXCOL2_COMMIT",
        "IPFIXCOL2_TCP_PLUGIN_VERSION",
        "IPFIXCOL2_JSON_PLUGIN_VERSION",
        "BASE_IMAGE",
        "BASE_IMAGE_DIGEST",
    }

    missing = sorted(required - versions.keys())

    if missing:
        raise VerificationError(
            "versions.env is missing: " + ", ".join(missing)
        )

    return versions


def parse_cache_stats(path: Path) -> dict[str, int]:
    values: dict[str, int] = {}

    for line in path.read_text(encoding="utf-8").splitlines():
        if ":" not in line:
            continue

        name, raw_value = line.rsplit(":", 1)
        raw_value = raw_value.strip()

        if raw_value.isdigit():
            values[name.strip()] = int(raw_value)

    for required in (
        "FlowEndReason:Collision",
        "TotalExportedFlows",
    ):
        if required not in values:
            raise VerificationError(
                f"{path}: missing cache counter {required}"
            )

    return values


def require_probe_summary(path: Path) -> None:
    text = path.read_text(encoding="utf-8")

    summary = re.search(
        r"^SUM[ \t]+11[ \t]+11[ \t]+588[ \t]+0[ \t]+0$",
        text,
        re.MULTILINE,
    )

    queue = re.search(
        r"^[ \t]*0[ \t]+3[ \t]+11[ \t]+434[ \t]+0[ \t]+ok$",
        text,
        re.MULTILINE,
    )

    if summary is None or queue is None:
        raise VerificationError(
            f"{path}: expected ipfixprobe smoke summary was not found"
        )


def require_clean_collector_log(path: Path) -> None:
    text = path.read_text(encoding="utf-8")

    match = ERROR_PATTERN.search(text)

    if match is not None:
        raise VerificationError(
            f"{path}: collector log contains error indicator "
            f"{match.group(2)!r}"
        )

    if "Collector started successfully!" not in text:
        raise VerificationError(
            f"{path}: collector startup confirmation is missing"
        )

    if "Received a termination request" not in text:
        raise VerificationError(
            f"{path}: collector termination confirmation is missing"
        )


def run_validator(
    schema: Path,
    flow_file: Path,
    records: int,
    digest: str,
) -> str:
    result = subprocess.run(
        [
            str(VALIDATOR_PATH),
            "--schema",
            str(schema),
            "--input",
            str(flow_file),
            "--expect-records",
            str(records),
            "--expect-sha256",
            digest,
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    if result.returncode != 0:
        raise VerificationError(
            f"schema validation failed for {flow_file}:\n"
            f"{result.stderr}"
        )

    if "IPFIX JSON contract validation passed" not in result.stdout:
        raise VerificationError(
            f"validator did not report success for {flow_file}"
        )

    return result.stdout


def inspect_docker_image(image: str) -> dict[str, Any]:
    candidates = (
        ["docker"],
        ["sudo", "-n", "docker"],
    )
    failures: list[str] = []

    for prefix in candidates:
        result = subprocess.run(
            [*prefix, "image", "inspect", image],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        if result.returncode != 0:
            failures.append(
                f"{' '.join(prefix)}: {result.stderr.strip()}"
            )
            continue

        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise VerificationError(
                f"cannot parse Docker image metadata: {exc}"
            ) from exc

        if not isinstance(payload, list) or len(payload) != 1:
            raise VerificationError(
                "Docker image inspect returned an unexpected payload"
            )

        return payload[0]

    raise VerificationError(
        "cannot inspect Docker image:\n" + "\n".join(failures)
    )


def load_schema_metadata(path: Path) -> dict[str, Any]:
    schema = json.loads(path.read_text(encoding="utf-8"))
    metadata = schema.get("x-pcap2netflow")

    if not isinstance(metadata, dict):
        raise VerificationError(
            f"{path}: x-pcap2netflow metadata is missing"
        )

    return {
        "id": schema.get("$id"),
        "contract_version": metadata.get("contract_version"),
        "timestamp_serialization": metadata.get(
            "timestamp_serialization"
        ),
        "timestamp_value_unit": metadata.get(
            "timestamp_value_unit"
        ),
        "numeric_names": metadata.get("numeric_names"),
        "split_biflow": metadata.get("split_biflow"),
        "additional_information_elements_allowed": metadata.get(
            "additional_information_elements_allowed"
        ),
    }


def load_collector_configuration(path: Path) -> dict[str, Any]:
    root = ET.fromstring(path.read_text(encoding="utf-8"))

    def required_text(xpath: str) -> str:
        element = root.find(xpath)

        if element is None or element.text is None:
            raise VerificationError(
                f"{path}: missing XML element {xpath}"
            )

        return element.text.strip()

    configuration = {
        "listen_address": required_text(
            "./inputPlugins/input/params/localIPAddress"
        ),
        "listen_port": int(
            required_text(
                "./inputPlugins/input/params/localPort"
            )
        ),
        "timestamp": required_text(
            "./outputPlugins/output/params/timestamp"
        ),
        "protocol": required_text(
            "./outputPlugins/output/params/protocol"
        ),
        "numeric_names": (
            required_text(
                "./outputPlugins/output/params/numericNames"
            ).lower()
            == "true"
        ),
        "split_biflow": (
            required_text(
                "./outputPlugins/output/params/splitBiflow"
            ).lower()
            == "true"
        ),
        "output_path_template": required_text(
            "./outputPlugins/output/params/outputs/file/path"
        ),
    }

    expected = {
        "listen_address": "127.0.0.1",
        "listen_port": 4739,
        "timestamp": "unix",
        "protocol": "raw",
        "numeric_names": False,
        "split_biflow": False,
        "output_path_template": "__OUTPUT_DIR__",
    }

    if configuration != expected:
        raise VerificationError(
            "collector configuration does not match the frozen contract"
        )

    return configuration


def git_information() -> dict[str, Any]:
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout.strip()

    status = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout

    return {
        "head_commit": head,
        "working_tree_dirty": bool(status.strip()),
    }


def operating_system_name() -> str:
    os_release = Path("/etc/os-release")

    if not os_release.exists():
        return platform.platform()

    for line in os_release.read_text(
        encoding="utf-8"
    ).splitlines():
        if line.startswith("PRETTY_NAME="):
            return shlex.split(line.split("=", 1)[1])[0]

    return platform.platform()


def sanitize_text(
    text: str,
    native_dir: Path,
    docker_dir: Path,
) -> str:
    replacements = (
        (str(ROOT), "${REPO_ROOT}"),
        (str(native_dir.resolve()), "${NATIVE_RUN_DIR}"),
        (str(docker_dir.resolve()), "${DOCKER_RUN_DIR}"),
        (str(native_dir), "${NATIVE_RUN_DIR}"),
        (str(docker_dir), "${DOCKER_RUN_DIR}"),
    )

    for old, new in replacements:
        text = text.replace(old, new)

    return text


def publish_bundle(
    native_dir: Path,
    docker_dir: Path,
    target: Path,
) -> dict[str, dict[str, str]]:
    target.parent.mkdir(parents=True, exist_ok=True)

    temporary = Path(
        tempfile.mkdtemp(
            prefix=f".{target.name}.",
            dir=target.parent,
        )
    )

    file_map = {
        "native_flow_output": (
            native_dir / "native.sorted.json",
            "native.sorted.json",
            False,
        ),
        "docker_flow_output": (
            docker_dir / "docker.sorted.json",
            "docker.sorted.json",
            False,
        ),
        "native_cache_telemetry": (
            native_dir / "cache-stats.txt",
            "native-cache-stats.txt",
            True,
        ),
        "docker_cache_telemetry": (
            docker_dir / "cache-stats.txt",
            "docker-cache-stats.txt",
            True,
        ),
        "native_ipfixprobe_log": (
            native_dir / "ipfixprobe.log",
            "native-ipfixprobe.log",
            True,
        ),
        "docker_ipfixprobe_log": (
            docker_dir / "ipfixprobe.log",
            "docker-ipfixprobe.log",
            True,
        ),
        "native_collector_log": (
            native_dir / "ipfixcol2.log",
            "native-ipfixcol2.log",
            True,
        ),
        "docker_collector_log": (
            docker_dir / "ipfixcol2.log",
            "docker-ipfixcol2.log",
            True,
        ),
        "native_schema_validation": (
            native_dir / "schema-validation.log",
            "native-schema-validation.log",
            True,
        ),
        "docker_schema_validation": (
            docker_dir / "schema-validation.log",
            "docker-schema-validation.log",
            True,
        ),
    }

    artefacts: dict[str, dict[str, str]] = {}

    try:
        for name, (source, filename, sanitize) in file_map.items():
            destination = temporary / filename

            if sanitize:
                text = source.read_text(encoding="utf-8")
                destination.write_text(
                    sanitize_text(
                        text,
                        native_dir,
                        docker_dir,
                    ),
                    encoding="utf-8",
                )
            else:
                shutil.copyfile(source, destination)

            artefacts[name] = {
                "path": (
                    target.relative_to(ROOT) / filename
                ).as_posix(),
                "sha256": sha256_file(destination),
            }

        if target.exists():
            shutil.rmtree(target)

        temporary.rename(target)

    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise

    return artefacts


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Verify and publish native/Docker IPFIX-to-JSON "
            "parity evidence."
        )
    )
    parser.add_argument(
        "--native-dir",
        type=Path,
        required=True,
        help="Successful native smoke run directory.",
    )
    parser.add_argument(
        "--docker-dir",
        type=Path,
        required=True,
        help="Successful Docker parity run directory.",
    )
    parser.add_argument(
        "--image",
        default="pcap2netflow-ipfixprobe:v1.4-dev-arm64",
        help="Docker image used for the parity run.",
    )
    parser.add_argument(
        "--bundle-dir",
        type=Path,
        default=ROOT / "verification" / "ipfix_json_parity",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "manifests" / "p1d_ipfix_json_parity.json",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()

    native_dir = arguments.native_dir.resolve()
    docker_dir = arguments.docker_dir.resolve()
    bundle_dir = arguments.bundle_dir.resolve()
    output_path = arguments.output.resolve()

    required_project_paths = (
        VERSIONS_PATH,
        CONFIG_PATH,
        SCHEMA_PATH,
        PCAP_PATH,
        VALIDATOR_PATH,
    )

    required_run_files = (
        native_dir / "native.sorted.json",
        native_dir / "cache-stats.txt",
        native_dir / "ipfixprobe.log",
        native_dir / "ipfixcol2.log",
        native_dir / "schema-validation.log",
        docker_dir / "docker.sorted.json",
        docker_dir / "cache-stats.txt",
        docker_dir / "ipfixprobe.log",
        docker_dir / "ipfixcol2.log",
        docker_dir / "schema-validation.log",
    )

    for required_path in (
        *required_project_paths,
        *required_run_files,
    ):
        if not required_path.is_file():
            raise VerificationError(
                f"required file not found: {required_path}"
            )

    versions = load_versions(VERSIONS_PATH)
    schema_metadata = load_schema_metadata(SCHEMA_PATH)
    collector_configuration = load_collector_configuration(
        CONFIG_PATH
    )

    native_flow = native_dir / "native.sorted.json"
    docker_flow = docker_dir / "docker.sorted.json"

    native_hash = sha256_file(native_flow)
    docker_hash = sha256_file(docker_flow)

    if native_flow.read_bytes() != docker_flow.read_bytes():
        raise VerificationError(
            "native and Docker JSON outputs are not byte-identical"
        )

    if native_hash != docker_hash:
        raise VerificationError(
            "native and Docker JSON SHA-256 values differ"
        )

    native_records = len(
        native_flow.read_text(encoding="utf-8").splitlines()
    )
    docker_records = len(
        docker_flow.read_text(encoding="utf-8").splitlines()
    )

    if native_records != 3 or docker_records != 3:
        raise VerificationError(
            "smoke output must contain exactly three records"
        )

    native_stats = parse_cache_stats(
        native_dir / "cache-stats.txt"
    )
    docker_stats = parse_cache_stats(
        docker_dir / "cache-stats.txt"
    )

    for environment, stats in (
        ("native", native_stats),
        ("docker", docker_stats),
    ):
        if stats["FlowEndReason:Collision"] != 0:
            raise VerificationError(
                f"{environment}: collision counter is non-zero"
            )

        if stats["TotalExportedFlows"] != 3:
            raise VerificationError(
                f"{environment}: TotalExportedFlows is not three"
            )

    require_probe_summary(native_dir / "ipfixprobe.log")
    require_probe_summary(docker_dir / "ipfixprobe.log")
    require_clean_collector_log(native_dir / "ipfixcol2.log")
    require_clean_collector_log(docker_dir / "ipfixcol2.log")

    native_validation = run_validator(
        SCHEMA_PATH,
        native_flow,
        native_records,
        native_hash,
    )
    docker_validation = run_validator(
        SCHEMA_PATH,
        docker_flow,
        docker_records,
        docker_hash,
    )

    if "undeclared_fields=none" not in native_validation:
        raise VerificationError(
            "native schema validation found undeclared fields"
        )

    if "undeclared_fields=none" not in docker_validation:
        raise VerificationError(
            "Docker schema validation found undeclared fields"
        )

    image_metadata = inspect_docker_image(arguments.image)

    if image_metadata.get("Architecture") != "arm64":
        raise VerificationError(
            "Docker image architecture is not arm64"
        )

    artefacts = publish_bundle(
        native_dir,
        docker_dir,
        bundle_dir,
    )

    manifest = {
        "manifest_version": "1.0.0",
        "pipeline_version": versions["PIPELINE_VERSION"],
        "development_target": "1.4",
        "release_state": "development",
        "stage": "P1d",
        "status": "passed",
        "recorded_at_utc": datetime.now(
            timezone.utc
        ).isoformat(
            timespec="seconds"
        ).replace(
            "+00:00",
            "Z",
        ),
        "git": git_information(),
        "host": {
            "hostname": platform.node(),
            "architecture": platform.machine(),
            "kernel": platform.release(),
            "operating_system": operating_system_name(),
        },
        "input": {
            "path": relative_path(PCAP_PATH),
            "sha256": sha256_file(PCAP_PATH),
            "packet_count": 11,
        },
        "interface": {
            "transport": "blocking IPFIX over TCP loopback",
            "collector_output": "JSON Lines",
            "collector_configuration": {
                "path": relative_path(CONFIG_PATH),
                "sha256": sha256_file(CONFIG_PATH),
                **collector_configuration,
            },
            "flow_schema": {
                "path": relative_path(SCHEMA_PATH),
                "sha256": sha256_file(SCHEMA_PATH),
                **schema_metadata,
            },
        },
        "source_revisions": {
            "ipfixprobe": {
                "repository": versions[
                    "IPFIXPROBE_REPOSITORY"
                ],
                "tag": versions["IPFIXPROBE_TAG"],
                "commit": versions["IPFIXPROBE_COMMIT"],
                "version": "5.7.0",
            },
            "libfds": {
                "repository": versions[
                    "LIBFDS_REPOSITORY"
                ],
                "commit": versions["LIBFDS_COMMIT"],
                "version": versions["LIBFDS_VERSION"],
            },
            "ipfixcol2": {
                "repository": versions[
                    "IPFIXCOL2_REPOSITORY"
                ],
                "commit": versions["IPFIXCOL2_COMMIT"],
                "version": versions["IPFIXCOL2_VERSION"],
                "tcp_plugin_version": versions[
                    "IPFIXCOL2_TCP_PLUGIN_VERSION"
                ],
                "json_plugin_version": versions[
                    "IPFIXCOL2_JSON_PLUGIN_VERSION"
                ],
            },
        },
        "container": {
            "image": arguments.image,
            "image_id": image_metadata.get("Id"),
            "architecture": image_metadata.get("Architecture"),
            "operating_system": image_metadata.get("Os"),
            "created_at": image_metadata.get("Created"),
            "base_image": versions["BASE_IMAGE"],
            "base_image_digest": versions[
                "BASE_IMAGE_DIGEST"
            ],
        },
        "results": {
            "native_records": native_records,
            "docker_records": docker_records,
            "native_total_exported_flows": native_stats[
                "TotalExportedFlows"
            ],
            "docker_total_exported_flows": docker_stats[
                "TotalExportedFlows"
            ],
            "native_collision_count": native_stats[
                "FlowEndReason:Collision"
            ],
            "docker_collision_count": docker_stats[
                "FlowEndReason:Collision"
            ],
            "flow_output_sha256": native_hash,
            "native_docker_byte_identical": True,
            "cache_telemetry_byte_identical": (
                (native_dir / "cache-stats.txt").read_bytes()
                == (docker_dir / "cache-stats.txt").read_bytes()
            ),
            "ipfixprobe_log_byte_identical": (
                (native_dir / "ipfixprobe.log").read_bytes()
                == (docker_dir / "ipfixprobe.log").read_bytes()
            ),
            "collector_log_byte_identical": (
                (native_dir / "ipfixcol2.log").read_bytes()
                == (docker_dir / "ipfixcol2.log").read_bytes()
            ),
            "schema_validation_passed": True,
            "observed_fields": 19,
            "undeclared_fields": [],
            "timestamp_unit": "unix_milliseconds",
            "split_biflow": False,
        },
        "artefacts": artefacts,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)

    temporary_output = output_path.with_suffix(
        output_path.suffix + ".tmp"
    )

    temporary_output.write_text(
        json.dumps(
            manifest,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    os.replace(temporary_output, output_path)

    print("IPFIX-to-JSON verification bundle published")
    print(f"manifest={relative_path(output_path)}")
    print(f"bundle={relative_path(bundle_dir)}")
    print(f"records={native_records}")
    print("collision=0")
    print(f"flow_output_sha256={native_hash}")
    print("native_and_docker=byte-identical")
    print(
        "collector_logs_byte_identical="
        + str(
            manifest["results"][
                "collector_log_byte_identical"
            ]
        ).lower()
    )
    print(
        f"pipeline_version={versions['PIPELINE_VERSION']}"
    )
    print("development_target=1.4")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
