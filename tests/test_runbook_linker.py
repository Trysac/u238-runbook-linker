"""Behavior tests for the public API of runbook_linker."""

from __future__ import annotations

import pytest

import runbook_linker


def test_normalize_trims_and_lowercases() -> None:
    assert runbook_linker.normalize("  Hello World ") == "hello world"


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_normalize_rejects_blank_input(value: str) -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        runbook_linker.normalize(value)


def test_version_is_semver() -> None:
    parts = runbook_linker.__version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)
