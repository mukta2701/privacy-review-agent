"""Unit tests for the identifier-aware keyword matcher in utils."""

import pytest

from privacy_review_agent.utils import (
    has_any_token,
    is_full_line_comment,
    split_identifier_parts,
)


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("name", True),
        ("userName", True),
        ("user_name", True),
        ("customer.name", True),
        ("NAME", True),
        ("filename", False),
        ("rename", False),
        ("names", False),
    ],
)
def test_name_matches_whole_word_parts_only(line, expected):
    assert has_any_token(line, {"name"}) is expected


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("lat", True),
        ("user.lat", True),
        ("translate", False),
        ("latitude", False),
    ],
)
def test_lat_matches_whole_word_parts_only(line, expected):
    assert has_any_token(line, {"lat"}) is expected


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("token", True),
        ("authToken", True),
        ("auth_token", True),
        ("max_tokens", False),
        ("tokenizer", False),
    ],
)
def test_token_matches_whole_word_parts_only(line, expected):
    assert has_any_token(line, {"token"}) is expected


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("firstName", True),
        ("first_name", True),
        ("FIRST_NAME", True),
        ("first-name", True),
        ("first_middle_name", False),
    ],
)
def test_multi_word_marker_needs_consecutive_parts(line, expected):
    assert has_any_token(line, {"first_name"}) is expected


def test_acronym_splits_do_not_crash_or_lose_parts():
    assert has_any_token("FIRST_NAME", {"first_name"}) is True
    assert has_any_token("userID", {"user_id"}) is True
    assert has_any_token("HTTPRequest", {"http"}) is True
    assert has_any_token("HTTPRequest", {"request"}) is True


def test_split_identifier_parts_handles_acronym_and_case_boundaries():
    assert split_identifier_parts("FIRST_NAME") == ["first", "name"]
    assert split_identifier_parts("userID") == ["user", "id"]
    assert split_identifier_parts("HTTPRequest") == ["http", "request"]
    assert split_identifier_parts("customer.name") == ["customer", "name"]


@pytest.mark.parametrize(
    ("line", "marker", "expected"),
    [
        ("console.log(x)", "console.log", True),
        ("myconsole.logger(x)", "console.log", False),
        ("print(x)", "print(", True),
        ("blueprint(x)", "print(", False),
        ("pprint(x)", "print(", False),
        ("fetch(url)", "fetch(", True),
        ("if (true) {", "if (true)", True),
        ("input=foo", "input=", True),
        ("rawinput=foo", "input=", False),
        ("consent=true", "consent = true", True),
        ("consent = true", "consent = true", True),
        ("privacy_check=false", "privacy_check = false", True),
    ],
)
def test_punctuation_markers_match_literally_on_part_boundaries(
    line, marker, expected
):
    assert has_any_token(line, {marker}) is expected


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("# print(user.email)", True),
        ("   # print(user.email)", True),
        ("// console.log(req.body)", True),
        ("   // console.log(req.body)", True),
        ("print(user.email)", False),
        ("x = 1  # print(user.email)", False),
    ],
)
def test_full_line_comment_detection(line, expected):
    assert is_full_line_comment(line) is expected
