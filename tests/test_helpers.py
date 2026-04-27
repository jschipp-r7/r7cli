"""Tests for shared helper functions in r7cli.helpers."""
from __future__ import annotations

import json
import operator
import tempfile
from pathlib import Path

import hypothesis.strategies as st
import pytest
from hypothesis import given, settings

from r7cli.helpers import (
    extract_item_id,
    extract_items,
    parse_cmp_expr,
    resolve_body,
)
from r7cli.models import UserInputError


# ---------------------------------------------------------------------------
# extract_items
# ---------------------------------------------------------------------------

class TestExtractItems:
    """Tests for extract_items — finds the largest list of dicts."""

    def test_flat_list_of_dicts(self):
        data = [{"id": 1}, {"id": 2}, {"id": 3}]
        assert extract_items(data) == data

    def test_empty_list(self):
        assert extract_items([]) == []

    def test_list_of_non_dicts(self):
        assert extract_items([1, 2, 3]) == []

    def test_dict_with_nested_list(self):
        data = {"results": [{"id": 1}, {"id": 2}], "count": 2}
        assert extract_items(data) == [{"id": 1}, {"id": 2}]

    def test_picks_largest_list(self):
        data = {
            "small": [{"a": 1}],
            "large": [{"b": 1}, {"b": 2}, {"b": 3}],
        }
        assert extract_items(data) == [{"b": 1}, {"b": 2}, {"b": 3}]

    def test_nested_dict(self):
        data = {"outer": {"inner": [{"id": 1}]}}
        assert extract_items(data) == [{"id": 1}]

    def test_non_dict_non_list(self):
        assert extract_items("string") == []
        assert extract_items(42) == []
        assert extract_items(None) == []

    @given(st.lists(st.fixed_dictionaries({"id": st.integers()}), min_size=1, max_size=20))
    @settings(max_examples=50)
    def test_roundtrip_flat_list(self, items):
        """A flat list of dicts should be returned as-is."""
        assert extract_items(items) == items

    @given(
        key=st.text(min_size=1, max_size=10, alphabet="abcdefghijklmnopqrstuvwxyz"),
        items=st.lists(st.fixed_dictionaries({"v": st.integers()}), min_size=1, max_size=10),
    )
    @settings(max_examples=50)
    def test_wrapped_in_dict(self, key, items):
        """Items wrapped in a dict should be extracted."""
        assert extract_items({key: items}) == items


# ---------------------------------------------------------------------------
# extract_item_id
# ---------------------------------------------------------------------------

class TestExtractItemId:
    """Tests for extract_item_id — pulls the best ID from a dict."""

    def test_id_field(self):
        assert extract_item_id({"id": "abc-123"}) == "abc-123"

    def test_underscore_id(self):
        assert extract_item_id({"_id": "mongo-id"}) == "mongo-id"

    def test_rrn_field(self):
        assert extract_item_id({"rrn": "rrn:rapid7:abc"}) == "rrn:rapid7:abc"

    def test_workflow_id(self):
        assert extract_item_id({"workflowId": "wf-1"}) == "wf-1"

    def test_job_id(self):
        assert extract_item_id({"job_id": "j-99"}) == "j-99"

    def test_priority_order(self):
        """'id' takes precedence over '_id', 'rrn', etc."""
        item = {"rrn": "rrn:x", "_id": "mongo", "id": "primary"}
        assert extract_item_id(item) == "primary"

    def test_no_id_fields(self):
        assert extract_item_id({"name": "foo", "status": "ok"}) == ""

    def test_empty_dict(self):
        assert extract_item_id({}) == ""

    def test_numeric_id_converted_to_str(self):
        assert extract_item_id({"id": 42}) == "42"

    @given(st.text(min_size=1, max_size=50))
    @settings(max_examples=50)
    def test_any_string_id(self, val):
        """Any non-empty string in 'id' should be returned."""
        assert extract_item_id({"id": val}) == val


# ---------------------------------------------------------------------------
# parse_cmp_expr
# ---------------------------------------------------------------------------

class TestParseCmpExpr:
    """Tests for parse_cmp_expr — parses '>=7.5' into (op, '7.5')."""

    def test_ge(self):
        func, val = parse_cmp_expr(">=7.5")
        assert func is operator.ge
        assert val == "7.5"

    def test_le(self):
        func, val = parse_cmp_expr("<=3")
        assert func is operator.le
        assert val == "3"

    def test_gt(self):
        func, val = parse_cmp_expr(">100")
        assert func is operator.gt
        assert val == "100"

    def test_lt(self):
        func, val = parse_cmp_expr("<0.5")
        assert func is operator.lt
        assert val == "0.5"

    def test_eq_explicit(self):
        func, val = parse_cmp_expr("=9.8")
        assert func is operator.eq
        assert val == "9.8"

    def test_eq_implicit(self):
        """No operator prefix defaults to eq."""
        func, val = parse_cmp_expr("42")
        assert func is operator.eq
        assert val == "42"

    def test_whitespace_stripped(self):
        func, val = parse_cmp_expr("  >= 7.5 ")
        assert func is operator.ge
        assert val == "7.5"

    def test_date_value(self):
        func, val = parse_cmp_expr(">=2025-01-01")
        assert func is operator.ge
        assert val == "2025-01-01"

    @given(
        st.sampled_from([">=", "<=", ">", "<", "="]),
        st.text(min_size=1, max_size=20, alphabet="0123456789.abcdefghijklmnopqrstuvwxyz-"),
    )
    @settings(max_examples=50)
    def test_operator_prefix_extracted(self, op, value):
        """Any operator prefix should be correctly split from the value."""
        func, val = parse_cmp_expr(f"{op}{value}")
        assert val == value.strip()
        expected = {">=": operator.ge, "<=": operator.le, ">": operator.gt,
                    "<": operator.lt, "=": operator.eq}
        assert func is expected[op]


# ---------------------------------------------------------------------------
# resolve_body
# ---------------------------------------------------------------------------

class TestResolveBody:
    """Tests for resolve_body — parses JSON from --data or --data-file."""

    def test_data_str(self):
        result = resolve_body('{"key": "value"}', None)
        assert result == {"key": "value"}

    def test_data_file(self, tmp_dir):
        f = tmp_dir / "body.json"
        f.write_text('{"from_file": true}')
        result = resolve_body(None, str(f))
        assert result == {"from_file": True}

    def test_both_raises(self):
        with pytest.raises(UserInputError, match="not both"):
            resolve_body('{"a":1}', "/some/file.json")

    def test_neither_returns_none(self):
        assert resolve_body(None, None) is None

    def test_invalid_json_raises(self):
        with pytest.raises(json.JSONDecodeError):
            resolve_body("not json", None)

    def test_large_file_rejected(self, tmp_dir):
        """Files over 10 MB should be rejected."""
        f = tmp_dir / "huge.json"
        # Write just over 10 MB
        f.write_text('{"x": "' + "a" * (10 * 1024 * 1024) + '"}')
        with pytest.raises(UserInputError, match="too large"):
            resolve_body(None, str(f))
