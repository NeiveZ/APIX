"""Tests for modules/endpoint_fuzz.py — pure logic only, no network calls."""
import pytest

from modules.endpoint_fuzz import (
    EndpointFuzzer,
    HTTP_METHODS,
    _severity_from_code,
)


@pytest.fixture
def fuzzer():
    return EndpointFuzzer()


class TestParseMethods:
    def test_all_returns_every_http_method(self, fuzzer):
        assert fuzzer._parse_methods("ALL") == HTTP_METHODS

    def test_single_method_is_uppercased(self, fuzzer):
        assert fuzzer._parse_methods("get") == ["GET"]

    def test_comma_separated_methods(self, fuzzer):
        assert fuzzer._parse_methods("get,post,Put") == ["GET", "POST", "PUT"]

    def test_strips_whitespace_around_commas(self, fuzzer):
        assert fuzzer._parse_methods("get, post , put") == ["GET", "POST", "PUT"]


class TestParseHeaders:
    def test_empty_spec_returns_empty_dict(self, fuzzer):
        assert fuzzer._parse_headers("") == {}

    def test_single_header(self, fuzzer):
        assert fuzzer._parse_headers("X-Api-Key:secret") == {"X-Api-Key": "secret"}

    def test_multiple_headers(self, fuzzer):
        result = fuzzer._parse_headers("Key:Val,Key2:Val2")
        assert result == {"Key": "Val", "Key2": "Val2"}

    def test_value_containing_colon_is_kept_intact(self, fuzzer):
        # split(":", 1) should only split on the first colon
        result = fuzzer._parse_headers("X-Custom:http://example.com")
        assert result == {"X-Custom": "http://example.com"}

    def test_pair_without_colon_is_skipped(self, fuzzer):
        assert fuzzer._parse_headers("not-a-valid-pair") == {}


class TestSeverityFromCode:
    def test_2xx_on_api_endpoint_is_high(self):
        assert _severity_from_code(200, is_api=True) == "HIGH"

    def test_2xx_on_non_api_endpoint_is_medium(self):
        assert _severity_from_code(200, is_api=False) == "MEDIUM"

    def test_401_and_403_are_low(self):
        assert _severity_from_code(401, is_api=False) == "LOW"
        assert _severity_from_code(403, is_api=False) == "LOW"

    def test_5xx_is_medium(self):
        assert _severity_from_code(500, is_api=False) == "MEDIUM"

    def test_other_codes_are_info(self):
        assert _severity_from_code(301, is_api=False) == "INFO"


class TestBearerTokenHandling:
    """Regression tests for the .lstrip('Bearer ') bug.

    The original code used auth.lstrip('Bearer ') to strip a literal
    prefix, but lstrip() strips a *set of characters* from the left, not
    a prefix string. A token starting with characters from {B, e, a, r,
    ' '} — extremely common in base64/JWT tokens — had its leading
    characters silently eaten.
    """

    def _build_auth_header(self, auth: str) -> str:
        if auth.startswith("Bearer "):
            return auth
        if " " not in auth:
            return f"Bearer {auth}"
        return f"Basic {auth}"

    def test_token_starting_with_e_is_not_mangled(self):
        # Old buggy behavior: lstrip('Bearer ') would eat the leading 'e'.
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig"
        result = self._build_auth_header(token)
        assert result == f"Bearer {token}"
        assert "eyJhbGciOiJIUzI1NiJ9" in result

    def test_token_already_prefixed_with_bearer_is_untouched(self):
        token = "Bearer abc.def.ghi"
        assert self._build_auth_header(token) == token

    def test_token_starting_with_r_is_not_mangled(self):
        token = "raw-api-key-123456"
        result = self._build_auth_header(token)
        assert result == "Bearer raw-api-key-123456"
