import pytest

from searxng_access.auth import parse_api_key, parse_bearer_token


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("Bearer abc", "abc"),
        ("bearer abc", "abc"),
        ("  Bearer   abc  ", "abc"),
        (None, None),
        ("", None),
        ("Basic abc", None),
        ("Bearer", None),
        ("Bearer abc extra", None),
    ],
)
def test_parse_bearer_token(header: str | None, expected: str | None) -> None:
    assert parse_bearer_token(header) == expected


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("abc", "abc"),
        ("  abc  ", "abc"),
        (None, None),
        ("", None),
        ("   ", None),
        ("abc def", None),
        ("abc\tdef", None),
    ],
)
def test_parse_api_key(header: str | None, expected: str | None) -> None:
    assert parse_api_key(header) == expected
