#!/usr/bin/env python3
"""Integration tests for the pcapfix repaired-or-original selector."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "06_pcapfix_select.py"
SMOKE = ROOT / "tests" / "data" / "smoke.pcap"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_manifest(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def run_selector(
    input_path: Path,
    root: Path,
    pcapfix_bin: str = "pcapfix",
) -> tuple[subprocess.CompletedProcess[str], Path, Path, Path]:
    work_dir = root / "work"
    output_path = root / "selected.pcap"
    manifest_path = root / "manifest.json"

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--input",
            str(input_path),
            "--work-dir",
            str(work_dir),
            "--output",
            str(output_path),
            "--manifest",
            str(manifest_path),
            "--pcapfix-bin",
            pcapfix_bin,
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )

    return result, output_path, manifest_path, work_dir


@unittest.skipUnless(
    shutil.which("pcapfix"),
    "pcapfix is required for the integration branch tests",
)
class PcapfixSelectionTests(unittest.TestCase):
    def test_good_capture_selects_unchanged_working_copy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            result, output, manifest_path, work = run_selector(
                SMOKE,
                root,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(output.is_file())
            self.assertFalse((work / "repaired.pcap").exists())

            manifest = load_manifest(manifest_path)

            self.assertEqual(
                manifest["decision"],
                "use_original_no_repair_needed",
            )
            self.assertFalse(manifest["touched"])
            self.assertEqual(
                manifest["pcapfix"]["exit_code"],
                0,
            )
            self.assertTrue(
                manifest["pcapfix"]["no_repair_marker_seen"]
            )
            self.assertFalse(
                manifest["repaired_artifact"]["exists"]
            )
            self.assertTrue(manifest["input"]["unchanged"])
            self.assertTrue(manifest["working_copy"]["unchanged"])
            self.assertEqual(
                sha256_file(output),
                sha256_file(SMOKE),
            )

    @unittest.skipUnless(
        shutil.which("capinfos"),
        "capinfos is required to validate repaired output",
    )
    def test_truncated_capture_selects_repaired_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            truncated = root / "truncated.pcap"
            original_bytes = SMOKE.read_bytes()

            self.assertGreater(len(original_bytes), 64)
            truncated.write_bytes(original_bytes[:-32])
            truncated_hash_before = sha256_file(truncated)

            result, output, manifest_path, work = run_selector(
                truncated,
                root,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(output.is_file())
            self.assertTrue((work / "repaired.pcap").is_file())
            self.assertEqual(
                sha256_file(truncated),
                truncated_hash_before,
            )
            self.assertNotEqual(
                sha256_file(output),
                truncated_hash_before,
            )

            manifest = load_manifest(manifest_path)

            self.assertEqual(
                manifest["decision"],
                "use_repaired_artifact",
            )
            self.assertTrue(manifest["touched"])
            self.assertEqual(
                manifest["pcapfix"]["exit_code"],
                0,
            )
            self.assertTrue(
                manifest["repaired_artifact"]["exists"]
            )
            self.assertGreater(
                manifest["repaired_artifact"]["size_bytes"],
                0,
            )
            self.assertTrue(manifest["input"]["unchanged"])
            self.assertTrue(manifest["working_copy"]["unchanged"])

            capinfos = subprocess.run(
                ["capinfos", str(output)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )

            self.assertEqual(
                capinfos.returncode,
                0,
                capinfos.stderr,
            )
            self.assertIn(
                "Number of packets:   11",
                capinfos.stdout,
            )
            self.assertNotIn(
                "cut short",
                capinfos.stderr.lower(),
            )

    def test_nonzero_pcapfix_exit_requires_manual_review(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake_pcapfix = root / "fake-pcapfix"

            fake_pcapfix.write_text(
                "#!/bin/sh\n"
                "echo 'synthetic pcapfix failure' >&2\n"
                "exit 7\n",
                encoding="utf-8",
            )
            fake_pcapfix.chmod(0o755)

            result, output, manifest_path, work = run_selector(
                SMOKE,
                root,
                str(fake_pcapfix),
            )

            self.assertEqual(result.returncode, 2)
            self.assertFalse(output.exists())
            self.assertTrue(manifest_path.is_file())

            manifest = load_manifest(manifest_path)

            self.assertEqual(
                manifest["status"],
                "manual_review_required",
            )
            self.assertEqual(
                manifest["decision"],
                "fail_for_manual_review",
            )
            self.assertIsNone(manifest["touched"])
            self.assertEqual(
                manifest["pcapfix"]["exit_code"],
                7,
            )
            self.assertFalse(
                manifest["repaired_artifact"]["exists"]
            )
            self.assertIn(
                "non-zero status 7",
                manifest["reason"],
            )
            self.assertIn(
                "synthetic pcapfix failure",
                (work / "pcapfix.stderr.txt").read_text(
                    encoding="utf-8"
                ),
            )


if __name__ == "__main__":
    unittest.main()
