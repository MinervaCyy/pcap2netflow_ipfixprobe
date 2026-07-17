#!/usr/bin/env python3
"""Offline fixture tests for the frozen CICIDS2018 Stage 2 pipeline."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "09_cicids2018_stage2_clean_day.py"
SMOKE = ROOT / "tests" / "data" / "smoke.pcap"

DAY = "Wednesday-14-02-2018"

REQUIRED_TOOLS = (
    "capinfos",
    "pcapfix",
    "reordercap",
    "mergecap",
)

SPEC = importlib.util.spec_from_file_location(
    "cicids2018_stage2_clean_day",
    SCRIPT,
)

if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to import Stage 2 module")

MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_inputs_manifest(
    root: Path,
    input_path: Path,
    source_key: str,
) -> Path:
    manifest = root / "inputs.json"

    manifest.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "day": DAY,
                "files": [
                    {
                        "source_key": source_key,
                        "path": input_path.name,
                    }
                ],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    return manifest


def run_stage2(
    root: Path,
    input_path: Path,
    *,
    source_key: str,
    pcapfix_bin: str = "pcapfix",
) -> tuple[
    subprocess.CompletedProcess[str],
    Path,
    Path,
    Path,
    Path,
]:
    inputs_manifest = write_inputs_manifest(
        root,
        input_path,
        source_key,
    )

    work_dir = root / "work"
    clean_dir = root / "clean"
    output_path = root / "output" / "merged.pcap"
    manifest_path = root / "manifests" / "stage2.json"

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--day",
            DAY,
            "--inputs-manifest",
            str(inputs_manifest),
            "--work-dir",
            str(work_dir),
            "--clean-dir",
            str(clean_dir),
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

    return (
        result,
        output_path,
        manifest_path,
        work_dir,
        clean_dir,
    )


def write_fake_capinfos(
    path: Path,
    stderr_lines: list[str],
) -> None:
    script = f"""#!/usr/bin/env python3
import os
import sys

input_path = sys.argv[-1]
size = os.path.getsize(input_path)

print(
    '"File name"\\t'
    '"Number of packets"\\t'
    '"File size (bytes)"\\t'
    '"Capture duration (seconds)"\\t'
    '"Start time"\\t'
    '"End time"\\t'
    '"Strict time order"'
)

print(
    f'"{{input_path}}"\\t'
    f'"10"\\t'
    f'"{{size}}"\\t'
    f'"0.009000"\\t'
    f'"1700000000.000000"\\t'
    f'"1700000000.009000"\\t'
    f'"True"'
)

for line in {stderr_lines!r}:
    print(line, file=sys.stderr)

raise SystemExit(1)
"""

    path.write_text(script, encoding="utf-8")
    path.chmod(
        path.stat().st_mode
        | stat.S_IXUSR
        | stat.S_IXGRP
        | stat.S_IXOTH
    )


@unittest.skipUnless(
    all(shutil.which(tool) for tool in REQUIRED_TOOLS),
    "capinfos, pcapfix, reordercap and mergecap are required",
)
class Stage2EndToEndFixtureTests(unittest.TestCase):
    def test_healthy_input_uses_untouched_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            input_path = root / "healthy.pcap"
            shutil.copy2(SMOKE, input_path)

            source_hash = sha256_file(input_path)

            (
                result,
                output,
                manifest_path,
                work_dir,
                clean_dir,
            ) = run_stage2(
                root,
                input_path,
                source_key=(
                    "Original Network Traffic and Log data/"
                    f"{DAY}/capEC2AMAZ-healthy.pcap"
                ),
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(output.is_file())
            self.assertTrue(manifest_path.is_file())
            self.assertEqual(sha256_file(input_path), source_hash)

            manifest = load_json(manifest_path)

            self.assertEqual(manifest["status"], "complete")
            self.assertEqual(
                manifest["policy"]["required_order"],
                MODULE.REQUIRED_ORDER,
            )
            self.assertEqual(manifest["counts"]["input_files"], 1)
            self.assertEqual(manifest["counts"]["touched"], 0)
            self.assertEqual(manifest["counts"]["untouched"], 1)
            self.assertEqual(
                manifest["counts"]["cut_short_inputs"],
                0,
            )

            record = manifest["files"][0]

            self.assertEqual(record["status"], "normalized")
            self.assertFalse(record["touched"])
            self.assertTrue(record["input_unchanged"])
            self.assertEqual(
                record["input_sha256_before"],
                source_hash,
            )
            self.assertEqual(
                record["input_sha256_after"],
                source_hash,
            )

            pre = record["capinfos_pre"]["summary"]

            self.assertEqual(pre["capinfos_exit_code"], 0)
            self.assertFalse(
                pre["accepted_cut_short_precheck"]
            )
            self.assertIsNone(pre["diagnostic_warning"])
            self.assertEqual(pre["packet_count"], 11)

            selection = record["pcapfix_selection"]

            self.assertEqual(
                selection["invocation"]["exit_code"],
                0,
            )
            self.assertGreaterEqual(
                selection["invocation"]["elapsed_seconds"],
                0,
            )
            self.assertTrue(
                Path(
                    selection["invocation"]["stdout_path"]
                ).is_file()
            )
            self.assertTrue(
                Path(
                    selection["invocation"]["stderr_path"]
                ).is_file()
            )
            self.assertEqual(
                selection["manifest"]["decision"],
                "use_original_no_repair_needed",
            )
            self.assertFalse(
                selection["manifest"]["touched"]
            )

            reorder = record["reordercap"]

            self.assertEqual(
                reorder["command"]["exit_code"],
                0,
            )
            self.assertTrue(
                Path(reorder["output_path"]).is_file()
            )
            self.assertEqual(
                reorder["input_sha256"],
                source_hash,
            )

            self.assertEqual(
                manifest["mergecap"]["command"]["exit_code"],
                0,
            )
            self.assertEqual(
                manifest["mergecap"]["output_format"],
                "pcap",
            )
            self.assertTrue(manifest["mergecap"]["published"])

            post = manifest["capinfos_post"]["summary"]

            self.assertEqual(post["capinfos_exit_code"], 0)
            self.assertTrue(post["strict_time_order"])
            self.assertEqual(post["packet_count"], 11)

            self.assertEqual(
                manifest["final_output"]["sha256"],
                sha256_file(output),
            )
            self.assertTrue(
                manifest["final_output"][
                    "published_atomically_from_candidate"
                ]
            )
            self.assertTrue(any(clean_dir.iterdir()))
            self.assertTrue(work_dir.is_dir())

    def test_truncated_input_uses_repaired_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            input_path = root / "truncated.pcap"
            input_path.write_bytes(SMOKE.read_bytes()[:-32])

            source_hash = sha256_file(input_path)

            (
                result,
                output,
                manifest_path,
                _work_dir,
                _clean_dir,
            ) = run_stage2(
                root,
                input_path,
                source_key=(
                    "Original Network Traffic and Log data/"
                    f"{DAY}/capEC2AMAZ-truncated.pcap"
                ),
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(output.is_file())
            self.assertEqual(sha256_file(input_path), source_hash)

            manifest = load_json(manifest_path)

            self.assertEqual(manifest["status"], "complete")
            self.assertEqual(manifest["counts"]["touched"], 1)
            self.assertEqual(manifest["counts"]["untouched"], 0)
            self.assertEqual(
                manifest["counts"]["cut_short_inputs"],
                1,
            )

            record = manifest["files"][0]

            self.assertTrue(record["touched"])
            self.assertTrue(record["input_unchanged"])

            pre = record["capinfos_pre"]["summary"]

            self.assertEqual(pre["capinfos_exit_code"], 1)
            self.assertTrue(
                pre["accepted_cut_short_precheck"]
            )
            self.assertEqual(
                pre["diagnostic_warning"],
                (
                    "input capture is cut short in the "
                    "middle of a packet"
                ),
            )
            self.assertEqual(pre["packet_count"], 10)

            selection = record["pcapfix_selection"]["manifest"]

            self.assertEqual(
                selection["decision"],
                "use_repaired_artifact",
            )
            self.assertTrue(selection["touched"])
            self.assertEqual(
                selection["pcapfix"]["exit_code"],
                0,
            )
            self.assertTrue(
                selection["repaired_artifact"]["exists"]
            )
            self.assertGreater(
                selection["repaired_artifact"]["size_bytes"],
                0,
            )

            self.assertNotEqual(
                record["reordercap"]["input_sha256"],
                source_hash,
            )

            post = manifest["capinfos_post"]["summary"]

            self.assertEqual(post["capinfos_exit_code"], 0)
            self.assertTrue(post["strict_time_order"])
            self.assertEqual(post["packet_count"], 11)

    def test_nonzero_pcapfix_requires_manual_review(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            input_path = root / "failure.pcap"
            shutil.copy2(SMOKE, input_path)

            source_hash = sha256_file(input_path)
            fake_pcapfix = root / "fake-pcapfix"

            fake_pcapfix.write_text(
                "#!/bin/sh\n"
                "echo 'synthetic pcapfix failure' >&2\n"
                "exit 7\n",
                encoding="utf-8",
            )
            fake_pcapfix.chmod(0o755)

            (
                result,
                output,
                manifest_path,
                _work_dir,
                clean_dir,
            ) = run_stage2(
                root,
                input_path,
                source_key=(
                    "Original Network Traffic and Log data/"
                    f"{DAY}/capEC2AMAZ-failure.pcap"
                ),
                pcapfix_bin=str(fake_pcapfix),
            )

            self.assertEqual(
                result.returncode,
                MODULE.MANUAL_REVIEW_EXIT_CODE,
            )
            self.assertFalse(output.exists())
            self.assertTrue(manifest_path.is_file())
            self.assertEqual(sha256_file(input_path), source_hash)

            manifest = load_json(manifest_path)

            self.assertEqual(
                manifest["status"],
                "manual_review_required",
            )
            self.assertEqual(
                manifest["error"]["exit_code"],
                MODULE.MANUAL_REVIEW_EXIT_CODE,
            )
            self.assertEqual(manifest["counts"]["touched"], 0)
            self.assertEqual(manifest["counts"]["untouched"], 0)
            self.assertEqual(
                manifest["counts"]["cut_short_inputs"],
                0,
            )
            self.assertIsNone(manifest["mergecap"])
            self.assertIsNone(manifest["capinfos_post"])
            self.assertIsNone(manifest["final_output"])

            record = manifest["files"][0]

            self.assertEqual(
                record["status"],
                "manual_review_required",
            )

            selection = record["pcapfix_selection"]

            self.assertEqual(
                selection["invocation"]["exit_code"],
                MODULE.MANUAL_REVIEW_EXIT_CODE,
            )
            self.assertEqual(
                selection["manifest"]["status"],
                "manual_review_required",
            )
            self.assertEqual(
                selection["manifest"]["decision"],
                "fail_for_manual_review",
            )
            self.assertIsNone(
                selection["manifest"]["touched"]
            )
            self.assertEqual(
                selection["manifest"]["pcapfix"]["exit_code"],
                7,
            )

            pcapfix_stderr = Path(
                selection["manifest"]["pcapfix"]["stderr_path"]
            ).read_text(encoding="utf-8")

            self.assertIn(
                "synthetic pcapfix failure",
                pcapfix_stderr,
            )
            self.assertTrue(clean_dir.is_dir())
            self.assertEqual(list(clean_dir.iterdir()), [])


@unittest.skipUnless(
    shutil.which("capinfos"),
    "capinfos is required for diagnostic-boundary tests",
)
class CapinfosDiagnosticBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.truncated = self.root / "truncated.pcap"
        self.truncated.write_bytes(SMOKE.read_bytes()[:-32])
        self.capinfos = Path(
            shutil.which("capinfos") or ""
        ).resolve()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_real_cut_short_precheck_is_accepted(self) -> None:
        result = MODULE.run_capinfos(
            executable=self.capinfos,
            input_path=self.truncated,
            log_dir=self.root / "accepted",
            prefix="capinfos_pre",
            allow_cut_short_precheck=True,
        )

        self.assertEqual(
            result["summary"]["capinfos_exit_code"],
            1,
        )
        self.assertTrue(
            result["summary"][
                "accepted_cut_short_precheck"
            ]
        )

    def test_unrelated_rc1_is_rejected(self) -> None:
        fake = self.root / "fake-unrelated"

        write_fake_capinfos(
            fake,
            [
                "capinfos: synthetic unrelated read failure",
            ],
        )

        with self.assertRaises(MODULE.Stage2Error):
            MODULE.run_capinfos(
                executable=fake,
                input_path=self.truncated,
                log_dir=self.root / "unrelated",
                prefix="capinfos_pre",
                allow_cut_short_precheck=True,
            )

    def test_compound_diagnostic_is_rejected(self) -> None:
        fake = self.root / "fake-compound"
        quoted = str(self.truncated)

        write_fake_capinfos(
            fake,
            [
                (
                    "capinfos: An error occurred after reading "
                    f'10 packets from "{quoted}".'
                ),
                (
                    f'capinfos: The file "{quoted}" appears to '
                    "have been cut short in the middle of a packet."
                ),
                (
                    "(will continue anyway, checksums might "
                    "be incorrect)"
                ),
                "capinfos: additional synthetic corruption",
            ],
        )

        with self.assertRaises(MODULE.Stage2Error):
            MODULE.run_capinfos(
                executable=fake,
                input_path=self.truncated,
                log_dir=self.root / "compound",
                prefix="capinfos_pre",
                allow_cut_short_precheck=True,
            )

    def test_postcheck_remains_strict(self) -> None:
        with self.assertRaises(MODULE.Stage2Error):
            MODULE.run_capinfos(
                executable=self.capinfos,
                input_path=self.truncated,
                log_dir=self.root / "post",
                prefix="capinfos_post",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
