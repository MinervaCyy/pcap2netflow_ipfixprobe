#!/usr/bin/env python3
"""Shared condition-operator semantics for CICIDS2018 labelling rules."""

from __future__ import annotations

from numbers import Real
from typing import Any


SUPPORTED_OPERATORS = frozenset({
    "==",
    "<",
    "<=",
    ">",
    ">=",
    "not_in",
})


def _require_number(value: Any, field_name: str) -> Real:
    if isinstance(value, bool) or not isinstance(value, Real):
        raise TypeError(f"{field_name} must be numeric")
    return value


def evaluate_condition(
    actual: Any,
    operator: str,
    expected: Any,
) -> bool:
    """Evaluate one frozen CICIDS2018 rule condition."""

    if operator not in SUPPORTED_OPERATORS:
        raise ValueError(f"unsupported operator: {operator!r}")

    if operator == "not_in":
        if not isinstance(expected, list):
            raise TypeError("not_in expected value must be a list")
        if not expected:
            raise ValueError("not_in expected list must not be empty")
        return actual not in expected

    actual_number = _require_number(actual, "actual")
    expected_number = _require_number(expected, "expected")

    if operator == "==":
        return actual_number == expected_number
    if operator == "<":
        return actual_number < expected_number
    if operator == "<=":
        return actual_number <= expected_number
    if operator == ">":
        return actual_number > expected_number
    if operator == ">=":
        return actual_number >= expected_number

    raise AssertionError("unreachable operator branch")
