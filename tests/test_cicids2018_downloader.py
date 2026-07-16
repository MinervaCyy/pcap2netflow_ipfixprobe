#!/usr/bin/env python3
"""Local integration tests for the CICIDS2018 archive downloader."""

from __future__ import annotations

import hashlib
import json
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import contextmanager
from datetime import datetime, timezone
from email.utils import format_datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "08_cicids2018_download_archive.py"

PAYLOAD = (
    b"pcap2netflow-download-fixture-"
    * 256
)
EXPECTED_ETAG = "0123456789abcdef0123456789abcdef-1"
LAST_MODIFIED_DT = datetime(
    2018,
    10,
    11,
    12,
    22,
    3,
    tzinfo=timezone.utc,
)
LAST_MODIFIED_HTTP = format_datetime(
    LAST_MODIFIED_DT,
    usegmt=True,
)
LAST_MODIFIED_ISO = "2018-10-11T12:22:03Z"


class ServerState:
    def __init__(
        self,
        *,
        payload: bytes = PAYLOAD,
        etag: str = EXPECTED_ETAG,
        fail_first_get: bool = False,
        always_partial: bool = False,
        partial_bytes: int = 64,
    ) -> None:
        self.payload = payload
        self.etag = etag
        self.fail_first_get = fail_first_get
        self.always_partial = always_partial
        self.partial_bytes = partial_bytes
        self.head_count = 0
        self.get_count = 0
        self.range_headers: list[str | None] = []
        self.if_match_headers: list[str | None] = []
        self.if_unmodified_headers: list[str | None] = []


def make_handler(
    state: ServerState,
) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(
            self,
            format: str,
            *args: Any,
        ) -> None:
            return

        def common_headers(
            self,
            *,
            content_length: int,
        ) -> None:
            self.send_header(
                "Content-Length",
                str(content_length),
            )
            self.send_header("ETag", f'"{state.etag}"')
            self.send_header(
                "Last-Modified",
                LAST_MODIFIED_HTTP,
            )
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Connection", "close")

        def do_HEAD(self) -> None:
            state.head_count += 1
            self.send_response(200)
            self.common_headers(
                content_length=len(state.payload),
            )
            self.end_headers()

        def do_GET(self) -> None:
            state.get_count += 1

            range_header = self.headers.get("Range")
            if_match = self.headers.get("If-Match")
            if_unmodified = self.headers.get(
                "If-Unmodified-Since"
            )

            state.range_headers.append(range_header)
            state.if_match_headers.append(if_match)
            state.if_unmodified_headers.append(
                if_unmodified
            )

            if if_match != f'"{state.etag}"':
                self.send_response(412)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                return

            if if_unmodified != LAST_MODIFIED_HTTP:
                self.send_response(412)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                return

            start = 0

            if range_header is not None:
                prefix = "bytes="

                if not range_header.startswith(prefix):
                    self.send_response(416)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return

                start_text = range_header[
                    len(prefix):
                ].split("-", 1)[0]

                try:
                    start = int(start_text)
                except ValueError:
                    self.send_response(416)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return

                if start >= len(state.payload):
                    self.send_response(416)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return

            remaining = state.payload[start:]

            should_partial = (
                state.always_partial
                or (
                    state.fail_first_get
                    and state.get_count == 1
                )
            )

            if range_header is None:
                self.send_response(200)
                self.common_headers(
                    content_length=len(remaining),
                )
            else:
                self.send_response(206)
                self.common_headers(
                    content_length=len(remaining),
                )
                self.send_header(
                    "Content-Range",
                    (
                        f"bytes {start}-"
                        f"{len(state.payload) - 1}/"
                        f"{len(state.payload)}"
                    ),
                )

            self.end_headers()

            if should_partial:
                amount = min(
                    state.partial_bytes,
                    len(remaining),
                )
                self.wfile.write(remaining[:amount])
                self.wfile.flush()

                try:
                    self.connection.shutdown(
                        socket.SHUT_RDWR
                    )
                except OSError:
                    pass

                self.connection.close()
                return

            self.wfile.write(remaining)
            self.wfile.flush()

    return Handler


@contextmanager
def fixture_server(
    state: ServerState,
) -> Iterator[str]:
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        make_handler(state),
    )

    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True,
    )
    thread.start()

    host, port = server.server_address

    try:
        yield f"http://{host}:{port}/pcap.zip"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def write_verification(
    path: Path,
    *,
    url: str,
    etag: str = EXPECTED_ETAG,
    size_bytes: int = len(PAYLOAD),
) -> None:
    payload = {
        "schema_version": "1.0",
        "record_type": (
            "cicids2018_wednesday_download_preflight_verification"
        ),
        "status": "preflight_passed_download_not_started",
        "source_preflight": {
            "sha256": "fixture-preflight-sha256",
            "object_downloads_performed": 0,
        },
        "formal_inventory": {
            "inventory_sha256": "fixture-inventory-sha256",
        },
        "selected_object": {
            "day": "Wednesday-14-02-2018",
            "key": (
                "Original Network Traffic and Log data/"
                "Wednesday-14-02-2018/pcap.zip"
            ),
            "url": url,
            "size_bytes": size_bytes,
            "etag": etag,
            "last_modified": LAST_MODIFIED_ISO,
        },
        "warnings": [],
        "gates": {
            "preflight": "passed",
            "downloader_freeze": "not_started",
            "dataset_download": "not_started",
            "archive_inspection": "not_started",
            "extraction": "closed",
        },
    }

    path.write_text(
        json.dumps(payload, indent=2) + "\n",
        encoding="utf-8",
    )


def run_downloader(
    root: Path,
    *,
    url: str,
    max_attempts: int = 3,
    etag: str = EXPECTED_ETAG,
) -> tuple[
    subprocess.CompletedProcess[str],
    Path,
    Path,
    Path,
]:
    verification = root / "verification.json"
    output = root / "raw" / "pcap.zip"
    manifest_dir = root / "manifest"

    write_verification(
        verification,
        url=url,
        etag=etag,
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--verification-record",
            str(verification),
            "--output",
            str(output),
            "--manifest-dir",
            str(manifest_dir),
            "--max-attempts",
            str(max_attempts),
            "--initial-backoff-seconds",
            "0",
            "--max-backoff-seconds",
            "0",
            "--total-timeout-seconds",
            "30",
            "--head-timeout-seconds",
            "10",
            "--connect-timeout-seconds",
            "5",
            "--reserve-bytes",
            "0",
            "--limit-rate",
            "0",
            "--speed-limit-bytes-per-second",
            "1",
            "--speed-time-seconds",
            "5",
            "--allow-http-for-tests",
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )

    return (
        result,
        output,
        output.with_name(output.name + ".part"),
        manifest_dir / "download_manifest.json",
    )


class DownloaderTests(unittest.TestCase):
    def test_fresh_download_publishes_exact_hashed_archive(
        self,
    ) -> None:
        state = ServerState()

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            with fixture_server(state) as url:
                result, output, part, manifest_path = (
                    run_downloader(root, url=url)
                )

            self.assertEqual(
                result.returncode,
                0,
                result.stderr,
            )
            self.assertEqual(output.read_bytes(), PAYLOAD)
            self.assertFalse(part.exists())

            expected_hash = hashlib.sha256(
                PAYLOAD
            ).hexdigest()

            sidecar = output.with_name(
                output.name + ".sha256"
            )

            self.assertEqual(
                sidecar.read_text(encoding="utf-8"),
                f"{expected_hash}  pcap.zip\n",
            )

            manifest = json.loads(
                manifest_path.read_text(
                    encoding="utf-8"
                )
            )

            self.assertEqual(
                manifest["status"],
                "complete",
            )
            self.assertEqual(
                manifest["final"]["size_bytes"],
                len(PAYLOAD),
            )
            self.assertEqual(
                manifest["final"]["sha256"],
                expected_hash,
            )
            self.assertTrue(
                manifest["final"][
                    "published_atomically_from_part"
                ]
            )
            self.assertFalse(
                manifest["extraction_authorised"]
            )
            self.assertEqual(state.head_count, 1)
            self.assertEqual(state.get_count, 1)
            self.assertEqual(
                state.if_match_headers,
                [f'"{EXPECTED_ETAG}"'],
            )
            self.assertEqual(
                state.if_unmodified_headers,
                [LAST_MODIFIED_HTTP],
            )

    def test_partial_failure_is_resumed_after_new_head_check(
        self,
    ) -> None:
        state = ServerState(
            fail_first_get=True,
            partial_bytes=128,
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            with fixture_server(state) as url:
                result, output, part, manifest_path = (
                    run_downloader(root, url=url)
                )

            self.assertEqual(
                result.returncode,
                0,
                result.stderr,
            )
            self.assertEqual(output.read_bytes(), PAYLOAD)
            self.assertFalse(part.exists())
            self.assertEqual(state.head_count, 2)
            self.assertEqual(state.get_count, 2)
            self.assertIsNone(state.range_headers[0])
            self.assertEqual(
                state.range_headers[1],
                "bytes=128-",
            )

            manifest = json.loads(
                manifest_path.read_text(
                    encoding="utf-8"
                )
            )

            self.assertEqual(
                len(manifest["attempts"]),
                2,
            )
            self.assertEqual(
                manifest["attempts"][0]["transfer"][
                    "curl_exit_code"
                ],
                18,
            )
            self.assertTrue(
                manifest["attempts"][1]["transfer"][
                    "resumed"
                ]
            )
            self.assertEqual(
                manifest["attempts"][1]["transfer"][
                    "http_code"
                ],
                206,
            )

    def test_identity_mismatch_quarantines_existing_part(
        self,
    ) -> None:
        state = ServerState(
            etag="ffffffffffffffffffffffffffffffff-1"
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw_dir = root / "raw"
            raw_dir.mkdir()
            part = raw_dir / "pcap.zip.part"
            part.write_bytes(PAYLOAD[:64])

            with fixture_server(state) as url:
                result, output, active_part, manifest_path = (
                    run_downloader(
                        root,
                        url=url,
                        etag=EXPECTED_ETAG,
                    )
                )

            self.assertEqual(result.returncode, 2)
            self.assertFalse(output.exists())
            self.assertFalse(active_part.exists())
            self.assertEqual(state.head_count, 1)
            self.assertEqual(state.get_count, 0)

            quarantined = list(
                raw_dir.glob(
                    "pcap.zip.part.remote-identity-mismatch."
                    "*.quarantine"
                )
            )

            self.assertEqual(len(quarantined), 1)
            self.assertEqual(
                quarantined[0].read_bytes(),
                PAYLOAD[:64],
            )

            manifest = json.loads(
                manifest_path.read_text(
                    encoding="utf-8"
                )
            )

            self.assertEqual(
                manifest["status"],
                "manual_review_required",
            )
            self.assertIsNotNone(
                manifest["quarantined_part"]
            )
            self.assertFalse(
                manifest["extraction_authorised"]
            )

    def test_bounded_retry_exhaustion_retains_partial_file(
        self,
    ) -> None:
        state = ServerState(
            always_partial=True,
            partial_bytes=64,
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            with fixture_server(state) as url:
                result, output, part, manifest_path = (
                    run_downloader(
                        root,
                        url=url,
                        max_attempts=2,
                    )
                )

            self.assertEqual(result.returncode, 3)
            self.assertFalse(output.exists())
            self.assertTrue(part.exists())
            self.assertEqual(part.stat().st_size, 128)
            self.assertEqual(state.head_count, 2)
            self.assertEqual(state.get_count, 2)
            self.assertEqual(
                state.range_headers,
                [None, "bytes=64-"],
            )

            manifest = json.loads(
                manifest_path.read_text(
                    encoding="utf-8"
                )
            )

            self.assertEqual(
                manifest["status"],
                "retry_exhausted",
            )
            self.assertEqual(
                len(manifest["attempts"]),
                2,
            )
            self.assertFalse(
                manifest["extraction_authorised"]
            )


if __name__ == "__main__":
    unittest.main()
