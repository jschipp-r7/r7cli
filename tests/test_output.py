"""Tests for output formatting in r7cli.output."""
from __future__ import annotations

import json

import pytest

from r7cli.output import (
    apply_limit,
    format_output,
    search_field,
)


# ---------------------------------------------------------------------------
# format_output — JSON
# ---------------------------------------------------------------------------

class TestFormatOutputJson:
    """Tests for JSON output format."""

    def test_dict(self):
        data = {"name": "test", "id": 1}
        result = format_output(data, "json")
        assert json.loads(result) == data

    def test_list(self):
        data = [{"a": 1}, {"a": 2}]
        result = format_output(data, "json")
        assert json.loads(result) == data

    def test_pretty_printed(self):
        result = format_output({"k": "v"}, "json")
        assert "\n" in result  # indented

    def test_short_mode_one_line_per_row(self):
        data = [{"name": "a", "id": "1"}, {"name": "b", "id": "2"}]
        result = format_output(data, "json", short=True)
        lines = result.strip().split("\n")
        assert len(lines) == 2
        # Each line should be valid JSON
        for line in lines:
            json.loads(line)


# ---------------------------------------------------------------------------
# format_output — table
# ---------------------------------------------------------------------------

class TestFormatOutputTable:
    """Tests for table output format."""

    def test_dict_renders_grid(self):
        data = [{"name": "alice", "age": 30}]
        result = format_output(data, "table")
        assert "alice" in result
        assert "30" in result
        assert "+" in result  # grid border

    def test_empty_list(self):
        assert format_output([], "table") == ""


# ---------------------------------------------------------------------------
# format_output — CSV
# ---------------------------------------------------------------------------

class TestFormatOutputCsv:
    """Tests for CSV output format."""

    def test_dict_list(self):
        data = [{"name": "a", "val": "1"}, {"name": "b", "val": "2"}]
        result = format_output(data, "csv")
        lines = result.strip().split("\n")
        assert lines[0].strip() == "name,val"  # header (CSV uses \r\n)
        assert lines[1].strip() == "a,1"

    def test_empty_list(self):
        assert format_output([], "csv") == ""


# ---------------------------------------------------------------------------
# format_output — TSV
# ---------------------------------------------------------------------------

class TestFormatOutputTsv:
    """Tests for TSV output format."""

    def test_dict_list(self):
        data = [{"x": "1", "y": "2"}]
        result = format_output(data, "tsv")
        lines = result.strip().split("\n")
        assert lines[0] == "x\ty"
        assert lines[1] == "1\t2"


# ---------------------------------------------------------------------------
# apply_limit
# ---------------------------------------------------------------------------

class TestApplyLimit:
    """Tests for apply_limit — truncates the largest array."""

    def test_truncates_largest_list(self):
        data = {"items": [1, 2, 3, 4, 5], "meta": "ok"}
        result = apply_limit(data, 2)
        assert result["items"] == [1, 2]
        assert result["meta"] == "ok"

    def test_non_dict_unchanged(self):
        assert apply_limit([1, 2, 3], 1) == [1, 2, 3]

    def test_no_lists_unchanged(self):
        data = {"a": 1, "b": "two"}
        assert apply_limit(data, 1) == data

    def test_limit_larger_than_list(self):
        data = {"items": [1, 2]}
        result = apply_limit(data, 100)
        assert result["items"] == [1, 2]


# ---------------------------------------------------------------------------
# search_field
# ---------------------------------------------------------------------------

class TestSearchField:
    """Tests for search_field — recursive field name search."""

    def test_flat_dict(self):
        assert search_field({"name": "alice"}, "name") == ["alice"]

    def test_nested_dict(self):
        data = {"outer": {"inner": {"target": 42}}}
        assert search_field(data, "target") == [42]

    def test_list_of_dicts(self):
        data = [{"id": 1}, {"id": 2}, {"id": 3}]
        assert search_field(data, "id") == [1, 2, 3]

    def test_no_match(self):
        assert search_field({"a": 1}, "missing") == []

    def test_deeply_nested(self):
        data = {"a": {"b": {"c": [{"d": {"target": "found"}}]}}}
        assert search_field(data, "target") == ["found"]

    def test_multiple_occurrences(self):
        data = {"name": "top", "child": {"name": "nested"}}
        assert search_field(data, "name") == ["top", "nested"]
