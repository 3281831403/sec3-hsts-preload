"""Public contract tests for the HSTS policy helpers."""

from hsts.policy import (
    check_max_age,
    check_subdomains,
    hsts_batch,
    narrow_only,
    parse_header,
)

FLOOR = 31536000


def _parsed(max_age, include_subdomains=True, preload=False, valid=True):
    return {
        "max_age": max_age,
        "include_subdomains": include_subdomains,
        "preload": preload,
        "valid": valid,
    }


def _policy():
    return {
        "min_max_age": FLOOR,
        "require_subdomains": True,
        "require_preload": False,
        "require_redirect": True,
    }


def test_parse_header_extracts_seconds_and_flags():
    parsed = parse_header("max-age=31536000; includeSubDomains; preload")
    assert parsed["max_age"] == FLOOR
    assert parsed["include_subdomains"] is True
    assert parsed["preload"] is True
    assert parsed["valid"] is True


def test_check_max_age_rejects_below_policy_floor():
    assert check_max_age(_parsed(FLOOR - 1), _policy()) is False
    assert check_max_age(_parsed(FLOOR), _policy()) is True


def test_check_subdomains_requires_include_subdomains():
    assert check_subdomains(_parsed(FLOOR, include_subdomains=False)) is False
    assert check_subdomains(_parsed(FLOOR, include_subdomains=True)) is True


def test_narrow_only_rejects_widening():
    old = _parsed(100, include_subdomains=True, preload=False)
    narrowed = _parsed(90, include_subdomains=True, preload=False)
    widened = _parsed(200, include_subdomains=True, preload=False)
    assert narrow_only(old, narrowed) is True
    assert narrow_only(old, widened) is False


def test_hsts_batch_checks_each_response_independently():
    policy = _policy()
    responses = [
        {
            "url": "https://example.com/",
            "scheme": "https",
            "status": 200,
            "headers": {
                "Strict-Transport-Security": (
                    "max-age=31536000; includeSubDomains"
                )
            },
        },
        {
            "url": "https://api.example.com/",
            "scheme": "https",
            "status": 200,
            "headers": {
                "Strict-Transport-Security": "max-age=100; includeSubDomains"
            },
        },
    ]
    result = hsts_batch(responses, policy)
    assert result["results"][0]["ok"] is True
    assert result["results"][1]["ok"] is False
    assert result["ok"] is False