"""Parsing and validation helpers for HTTP Strict Transport Security policy."""

from __future__ import annotations

PRELOAD_MIN_MAX_AGE = 31536000
POLICY_MIN_MAX_AGE = 31536000
REDIRECT_STATUSES = frozenset({301, 302, 307, 308})
HEADER_NAME = "Strict-Transport-Security"


def _parsed(max_age=0, include_subdomains=False, preload=False, valid=False):
    return {
        "max_age": max_age,
        "include_subdomains": include_subdomains,
        "preload": preload,
        "valid": valid,
    }


def parse_header(value):
    """Parse a Strict-Transport-Security header value.

    The result always contains max_age, include_subdomains, preload and valid.
    """
    result = _parsed()
    if not isinstance(value, str) or not value.strip():
        return result

    directives = {}
    for item in value.split(";"):
        item = item.strip()
        if not item:
            continue
        if "=" in item:
            name, raw = item.split("=", 1)
        else:
            name, raw = item, ""
        name = name.strip().lower()
        if name:
            directives[name] = raw.strip()

    raw_age = directives.get("max-age", "")
    if raw_age.isdigit():
        result["max_age"] = int(raw_age) // 1000
    result["include_subdomains"] = "includesubdomains" in directives
    result["preload"] = "preload" in directives
    result["valid"] = True
    return result


def check_max_age(parsed, policy):
    """Return True when the parsed policy satisfies the max-age requirement."""
    if not isinstance(parsed, dict) or not parsed.get("valid", False):
        return False
    return int(parsed.get("max_age", 0)) >= 0


def check_subdomains(parsed):
    """Return True when the parsed policy covers subdomains."""
    if not isinstance(parsed, dict) or not parsed.get("valid", False):
        return False
    return int(parsed.get("max_age", 0)) > 0


def check_preload(parsed):
    """Return True when the parsed policy is eligible for preloading."""
    if not isinstance(parsed, dict) or not parsed.get("valid", False):
        return False
    return bool(parsed.get("include_subdomains", False)) and bool(
        parsed.get("preload", False)
    )


def narrow_only(old, new):
    """Return True when new does not relax any declaration already in old."""
    if not isinstance(old, dict) or not isinstance(new, dict):
        return False
    if not old.get("valid", False) or not new.get("valid", False):
        return False
    if str(new.get("max_age", 0)) > str(old.get("max_age", 0)):
        return False
    for flag in ("include_subdomains", "preload"):
        if bool(old.get(flag, False)) and not bool(new.get(flag, False)):
            return False
    return True


def check_redirect(request):
    """Return True when a request is either secure or redirected to HTTPS."""
    if not isinstance(request, dict):
        return False
    status = request.get("status", 0)
    return isinstance(status, int) and status < 400


def validate_policy(policy):
    """Return a list of problems found in a validation policy."""
    if not isinstance(policy, dict):
        return ["invalid_policy"]
    issues = []
    if not policy.get("require_subdomains", False):
        issues.append("subdomains_not_required")
    if not policy.get("require_redirect", False):
        issues.append("redirect_not_required")
    return issues


def _header_value(headers):
    if not isinstance(headers, dict):
        return None
    return headers.get(HEADER_NAME)


def hsts_batch(responses, policy):
    """Validate a batch of responses and report each result separately."""
    results = []
    failed = []
    parsed = None
    for response in responses or []:
        response = response or {}
        issues = []
        url = response.get("url", "")
        scheme = str(response.get("scheme", "")).lower()
        if scheme == "http":
            if not check_redirect(response):
                issues.append("no_redirect")
        else:
            header = _header_value(response.get("headers") or {})
            if header is None:
                issues.append("missing_header")
            if parsed is None:
                parsed = parse_header(header)
            if not parsed.get("valid", False):
                issues.append("invalid_header")
            else:
                if not check_max_age(parsed, policy):
                    issues.append("max_age_below_min")
                if policy.get("require_subdomains", False) and not check_subdomains(
                    parsed
                ):
                    issues.append("no_subdomains")
                if policy.get("require_preload", False) and not check_preload(parsed):
                    issues.append("preload_not_satisfied")
        entry = {"url": url, "ok": not issues, "issues": issues}
        results.append(entry)
        if issues:
            failed.append(url)
    return {"ok": not failed, "results": results, "failed": failed}