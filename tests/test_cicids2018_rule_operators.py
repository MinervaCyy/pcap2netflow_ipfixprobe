#!/usr/bin/env python3
"""Regression tests for frozen CICIDS2018 rule operators."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "cicids2018_rule_operators.py"
)

SPEC = importlib.util.spec_from_file_location(
    "cicids2018_rule_operators",
    MODULE_PATH,
)

if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load operator module")

MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

evaluate_condition = MODULE.evaluate_condition


class RuleOperatorTests(unittest.TestCase):
    def test_less_than_or_equal_accepts_boundary(self) -> None:
        self.assertTrue(evaluate_condition(20, "<=", 20))

    def test_less_than_or_equal_accepts_lower_value(self) -> None:
        self.assertTrue(evaluate_condition(19, "<=", 20))

    def test_less_than_or_equal_rejects_higher_value(self) -> None:
        self.assertFalse(evaluate_condition(21, "<=", 20))

    def test_not_in_accepts_absent_value(self) -> None:
        self.assertTrue(
            evaluate_condition(12345, "not_in", [63782, 64144])
        )

    def test_not_in_rejects_present_value(self) -> None:
        self.assertFalse(
            evaluate_condition(63782, "not_in", [63782, 64144])
        )

    def test_not_in_rejects_empty_list(self) -> None:
        with self.assertRaises(ValueError):
            evaluate_condition(63782, "not_in", [])

    def test_not_in_rejects_non_list(self) -> None:
        with self.assertRaises(TypeError):
            evaluate_condition(63782, "not_in", (63782, 64144))

    def test_numeric_operator_rejects_wrong_type(self) -> None:
        with self.assertRaises(TypeError):
            evaluate_condition(20, "<=", "20")

    def test_unsupported_operator_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            evaluate_condition(20, "!=", 21)


if __name__ == "__main__":
    unittest.main()
