#!/usr/bin/env python3
"""Tests for the frozen CICIDS2018 formal-inventory collector."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "07_cicids2018_formal_inventory.py"

SPEC = importlib.util.spec_from_file_location(
    "cicids2018_formal_inventory",
    MODULE_PATH,
)

if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load inventory collector")

MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

classify_object = MODULE.classify_object
parse_list_page = MODULE.parse_list_page

PREFIX = (
    "Original Network Traffic and Log data/"
    "Wednesday-14-02-2018/"
)

SELECTION = {
    "selected_basename_exact": "pcap.zip",
    "explicitly_excluded_basenames": ["logs.zip"],
}


def xml_page(
    contents: list[tuple[str, int]],
    *,
    truncated: bool = False,
    next_token: str | None = None,
    key_count: int | None = None,
) -> bytes:
    effective_count = (
        len(contents)
        if key_count is None
        else key_count
    )

    object_xml = "".join(
        (
            "<Contents>"
            f"<Key>{key}</Key>"
            "<LastModified>2018-10-10T00:00:00.000Z</LastModified>"
            '<ETag>"etag-value"</ETag>'
            f"<Size>{size}</Size>"
            "</Contents>"
        )
        for key, size in contents
    )

    token_xml = (
        f"<NextContinuationToken>{next_token}</NextContinuationToken>"
        if next_token is not None
        else ""
    )

    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        f"<KeyCount>{effective_count}</KeyCount>"
        f"<IsTruncated>{str(truncated).lower()}</IsTruncated>"
        f"{token_xml}"
        f"{object_xml}"
        "</ListBucketResult>"
    ).encode("utf-8")


class FormalInventoryTests(unittest.TestCase):
    def test_parse_page_validates_key_count(self) -> None:
        body = xml_page(
            [
                (PREFIX, 0),
                (PREFIX + "logs.zip", 100),
                (PREFIX + "pcap.zip", 200),
            ]
        )

        page = parse_list_page(body)

        self.assertEqual(page["key_count"], 3)
        self.assertEqual(len(page["objects"]), 3)
        self.assertFalse(page["is_truncated"])
        self.assertIsNone(page["next_continuation_token"])

    def test_parse_page_rejects_key_count_mismatch(self) -> None:
        body = xml_page(
            [(PREFIX + "pcap.zip", 200)],
            key_count=2,
        )

        with self.assertRaisesRegex(
            ValueError,
            "KeyCount mismatch",
        ):
            parse_list_page(body)

    def test_truncated_page_requires_token(self) -> None:
        body = xml_page(
            [(PREFIX + "pcap.zip", 200)],
            truncated=True,
        )

        with self.assertRaisesRegex(
            ValueError,
            "NextContinuationToken",
        ):
            parse_list_page(body)

    def test_truncated_page_returns_token(self) -> None:
        body = xml_page(
            [(PREFIX + "pcap.zip", 200)],
            truncated=True,
            next_token="token-1",
        )

        page = parse_list_page(body)

        self.assertTrue(page["is_truncated"])
        self.assertEqual(
            page["next_continuation_token"],
            "token-1",
        )

    def test_directory_marker_is_ignored(self) -> None:
        result = classify_object(
            PREFIX,
            PREFIX,
            0,
            SELECTION,
        )

        self.assertEqual(
            result["decision"],
            "ignored_directory_marker",
        )

    def test_exact_direct_child_pcap_zip_is_selected(self) -> None:
        result = classify_object(
            PREFIX,
            PREFIX + "pcap.zip",
            100,
            SELECTION,
        )

        self.assertEqual(result["decision"], "selected")
        self.assertTrue(result["direct_child"])

    def test_empty_pcap_zip_is_unexpected(self) -> None:
        result = classify_object(
            PREFIX,
            PREFIX + "pcap.zip",
            0,
            SELECTION,
        )

        self.assertEqual(result["decision"], "unexpected")

    def test_logs_zip_is_explicitly_excluded(self) -> None:
        result = classify_object(
            PREFIX,
            PREFIX + "logs.zip",
            100,
            SELECTION,
        )

        self.assertEqual(result["decision"], "excluded")

    def test_nested_pcap_zip_is_rejected(self) -> None:
        result = classify_object(
            PREFIX,
            PREFIX + "nested/pcap.zip",
            100,
            SELECTION,
        )

        self.assertEqual(result["decision"], "unexpected")
        self.assertFalse(result["direct_child"])

    def test_unknown_direct_child_is_rejected(self) -> None:
        result = classify_object(
            PREFIX,
            PREFIX + "other.zip",
            100,
            SELECTION,
        )

        self.assertEqual(result["decision"], "unexpected")

    def test_outside_prefix_is_rejected(self) -> None:
        result = classify_object(
            PREFIX,
            "Other prefix/pcap.zip",
            100,
            SELECTION,
        )

        self.assertEqual(result["decision"], "unexpected")


if __name__ == "__main__":
    unittest.main()
