from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
from typing import Any
from urllib.parse import urljoin, urlparse


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


def _normalize_host(host: str) -> str:
    return host.lower().rstrip(".")


def _is_blocked(ip, blocked_nets) -> bool:
    if any(ip in net for net in blocked_nets):
        return True
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None and any(mapped in net for net in blocked_nets):
        return True
    return False


def _pin_ok(host: str, ips, pins, candidates, mode: str) -> bool:
    if host in pins:
        pinned = {ipaddress.ip_address(p) for p in pins[host]}
        return all(ip in pinned for ip in ips)
    if mode == "first_seen":
        if host in candidates:
            cand = set(candidates[host])
            return all(ip in cand for ip in ips)
        candidates[host] = list(ips)
        return True
    return False


def _path_allowed(path: str, host: str, policy: dict[str, Any]) -> bool:
    for sub in policy.get("denied_path_substrings") or []:
        if sub in path:
            return False
    group = None
    for name, hosts in (policy.get("host_groups") or {}).items():
        if host in hosts:
            group = name
            break
    if group is None:
        return False
    for entry in policy.get("path_allow") or []:
        if entry.get("group") != group:
            continue
        if "exact" in entry and path == entry["exact"]:
            return True
        if "prefix" in entry and path.startswith(entry["prefix"]):
            return True
    return False


def _check_hop(url, ctx) -> tuple[dict[str, Any], str | None]:
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    host = _normalize_host(parsed.hostname) if parsed.hostname else None
    port = parsed.port if parsed.port is not None else ctx["default_ports"].get(scheme)
    path = parsed.path or "/"
    hop = {
        "url": url,
        "scheme": scheme,
        "host": host,
        "port": port,
        "path": path,
        "resolved_ips": [],
    }

    if scheme not in ctx["allowed_schemes"] or host is None:
        return hop, "scheme_denied"
    if "@" in parsed.netloc:
        return hop, "userinfo_forbidden"

    literal = None
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None and ctx["forbid_ip_literal"]:
        return hop, "blocked_ip"

    if literal is not None:
        ips = [literal]
        resolved = [str(literal)]
    else:
        answers = ctx["answers"].get(host)
        if not answers:
            return hop, "nxdomain"
        ips = [ipaddress.ip_address(a) for a in answers]
        resolved = list(answers)
    hop["resolved_ips"] = resolved

    for ip in ips:
        if _is_blocked(ip, ctx["blocked_nets"]):
            return hop, "blocked_ip"
    if not _pin_ok(host, ips, ctx["pins"], ctx["candidates"], ctx["pin_mode"]):
        return hop, "pin_mismatch"
    if port not in ctx["allowed_ports"]:
        return hop, "port_denied"
    if not _path_allowed(path, host, ctx["policy"]):
        return hop, "path_denied"
    return hop, None


def _signature_ok(plan: dict[str, Any], policy: dict[str, Any]) -> bool:
    secret = policy.get("sig_secret")
    if not isinstance(secret, str):
        return False
    try:
        key = bytes.fromhex(secret)
    except ValueError:
        key = secret.encode("utf-8")
    signing_input = "{}|{}|{}".format(
        plan.get("method"), plan.get("url"), plan.get("body_sha256")
    )
    digest = hmac.new(key, signing_input.encode("ascii"), hashlib.sha256).digest()
    expected = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    provided = plan.get("sig")
    if not isinstance(provided, str):
        return False
    return hmac.compare_digest(expected, provided)


def admit_request(
    plan: dict[str, Any],
    resolver_snapshot: dict[str, Any],
    policy: dict[str, Any],
    pin_store: dict[str, Any],
) -> dict[str, Any]:
    """Admit an egress URL against a frozen resolver snapshot and pin store."""
    pins = pin_store.setdefault("pins", {})
    ctx = {
        "policy": policy,
        "answers": resolver_snapshot.get("answers") or {},
        "pins": pins,
        "candidates": {},
        "pin_mode": policy.get("pin_mode", "strict"),
        "blocked_nets": [
            ipaddress.ip_network(c) for c in policy.get("blocked_cidrs") or []
        ],
        "allowed_schemes": {s.lower() for s in policy.get("allowed_schemes") or []},
        "allowed_ports": set(policy.get("allowed_ports") or []),
        "default_ports": policy.get("default_ports") or {},
        "forbid_ip_literal": bool(policy.get("forbid_ip_literal")),
    }
    max_hops = policy.get("max_hops", 0)
    redirects = plan.get("redirects") or []

    hops: list[dict[str, Any]] = []
    reason: str | None = None
    url = plan.get("url")
    index = 0
    while True:
        hop, reason = _check_hop(url, ctx)
        hops.append(hop)
        if reason is not None:
            break
        if index < len(redirects):
            if index < max_hops:
                url = urljoin(url, redirects[index].get("location") or "")
                index += 1
                continue
            reason = "redirect_limit"
            break
        break

    if reason is None and policy.get("require_sig") and not _signature_ok(plan, policy):
        reason = "bad_signature"

    decision = "allow" if reason is None else "deny"
    if decision == "allow":
        for host, ips in ctx["candidates"].items():
            if host not in pins:
                pins[host] = [
                    str(ip)
                    for ip in sorted(ips, key=lambda i: (i.version, int(i)))
                ]

    last = hops[-1]
    return {
        "decision": decision,
        "reason_codes": [] if reason is None else [reason],
        "method": plan.get("method"),
        "final_url": last["url"],
        "scheme": last["scheme"],
        "host": last["host"],
        "port": last["port"],
        "path": last["path"],
        "resolved_ips": last["resolved_ips"],
        "hops": hops,
        "notes": [],
    }
