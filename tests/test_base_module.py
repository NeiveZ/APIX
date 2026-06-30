"""Tests for modules/base.py — the option-handling machinery every module relies on."""
from modules.endpoint_fuzz import EndpointFuzzer


def test_required_option_starts_unset():
    m = EndpointFuzzer()
    assert m.get_option("TARGET") == ""


def test_set_option_is_case_insensitive_on_name():
    m = EndpointFuzzer()
    assert m.set_option("target", "https://api.example.com") is True
    assert m.get_option("TARGET") == "https://api.example.com"


def test_set_unknown_option_returns_false():
    m = EndpointFuzzer()
    assert m.set_option("NOT_A_REAL_OPTION", "value") is False


def test_validate_fails_when_required_option_is_unset():
    m = EndpointFuzzer()
    assert m._validate() is False


def test_validate_passes_once_required_option_is_set():
    m = EndpointFuzzer()
    m.set_option("TARGET", "https://api.example.com")
    assert m._validate() is True


def test_run_returns_empty_list_without_required_option():
    # run() must short-circuit via _validate() rather than crash when a
    # required option (TARGET) was never set.
    m = EndpointFuzzer()
    assert m.run() == []
