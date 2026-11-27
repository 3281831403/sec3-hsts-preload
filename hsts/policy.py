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


def _as_int(value, default=0):
    """Best-effort integer conversion that never raises."""
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def parse_header(value):
    """Parse a Strict-Transport-Security header value.

    The result always contains max_age, include_subdomains, preload and valid.
    Per RFC 6797 ``max-age`` is mandatory and expressed in seconds: a header
    without a numeric max-age is reported as invalid.
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
        if name and name not in directives:
            directives[name] = raw.strip()

    raw_age = directives.get("max-age")
    if raw_age is None or not raw_age.isdigit():
        return result

    result["max_age"] = int(raw_age)
    result["include_subdomains"] = "includesubdomains" in directives
    result["preload"] = "preload" in directives
    result["valid"] = True
    return result


def check_max_age(parsed, policy=None):
    """Return True when the parsed policy meets the policy max-age floor."""
    if not isinstance(parsed, dict) or not parsed.get("valid", False):
        return False
    floor = POLICY_MIN_MAX_AGE
    if isinstance(policy, dict):
        configured = policy.get("min_max_age", POLICY_MIN_MAX_AGE)
        if isinstance(configured, int) and not isinstance(configured, bool):
            floor = configured
    return _as_int(parsed.get("max_age", 0)) >= floor


def check_subdomains(parsed):
    """Return True when the parsed policy covers subdomains."""
    if not isinstance(parsed, dict) or not parsed.get("valid", False):
        return False
    return bool(parsed.get("include_subdomains", False))


def check_preload(parsed):
    """Return True when the parsed policy is eligible for preloading.

    Preloading only takes effect when ``preload`` and ``includeSubDomains``
    are declared together, and the max-age reaches the preload minimum.
    """
    if not isinstance(parsed, dict) or not parsed.get("valid", False):
        return False
    if not parsed.get("include_subdomains", False):
        return False
    if not parsed.get("preload", False):
        return False
    return _as_int(parsed.get("max_age", 0)) >= PRELOAD_MIN_MAX_AGE


def narrow_only(old, new):
    """Return True when new does not relax any declaration already in old."""
    if not isinstance(old, dict) or not isinstance(new, dict):
        return False
    if not old.get("valid", False) or not new.get("valid", False):
        return False
    if _as_int(new.get("max_age", 0)) > _as_int(old.get("max_age", 0)):
        return False
    for flag in ("include_subdomains", "preload"):
        if bool(old.get(flag, False)) and not bool(new.get(flag, False)):
            return False
    return True


def check_redirect(request):
    """Return True when a plaintext request is redirected to HTTPS."""
    if not isinstance(request, dict):
        return False
    status = request.get("status", 0)
    if isinstance(status, bool) or status not in REDIRECT_STATUSES:
        return False
    location = request.get("location")
    if isinstance(location, str) and "://" in location:
        if not location.strip().lower().startswith("https://"):
            return False
    return True


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
    if not isinstance(policy, dict):
        policy = {}
    results = []
    failed = []
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
                # Missing header and unparseable header are distinct failures.
                parsed = _parsed()
                issues.append("missing_header")
            else:
                parsed = parse_header(header)
                if not parsed.get("valid", False):
                    issues.append("invalid_header")
            if parsed.get("valid", False):
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
