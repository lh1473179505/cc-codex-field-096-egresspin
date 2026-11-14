from __future__ import annotations

from typing import Any
from urllib.parse import urlparse


def _effective_port(parsed) -> int | None:
    if parsed.port is not None:
        return parsed.port
    if parsed.scheme == "http":
        return 80
    if parsed.scheme == "https":
        return 443
    return None


def inspect_plan(plan: dict[str, Any]) -> dict[str, Any]:
    """Parse a request plan. Does not resolve or follow redirects."""
    parsed = urlparse(plan.get("url") or "")
    redirects = plan.get("redirects") or []
    return {
        "method": plan.get("method"),
        "scheme": parsed.scheme,
        "host": parsed.hostname,
        "port": _effective_port(parsed),
        "path": parsed.path or "/",
        "redirects": redirects,
    }


def admit_request(
    plan: dict[str, Any],
    resolver_snapshot: dict[str, Any],
    policy: dict[str, Any],
    pin_store: dict[str, Any],
) -> dict[str, Any]:
    """Admit an egress URL. Stub — raise until implemented."""
    raise NotImplementedError(
        "egresspin.engine.admit_request is not implemented yet; inspect works"
    )
