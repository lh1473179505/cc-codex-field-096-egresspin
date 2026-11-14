# egresspin admit rules

An egress admission checks a **request plan** before any socket is
opened. Name resolution uses only the frozen snapshot. Pins remember
which addresses a hostname is allowed to use. A valid request
signature never skips the other gates.

## Plan JSON

```json
{
  "method": "GET",
  "url": "https://api.example.test/healthz",
  "body_sha256": "<lowercase hex sha256>",
  "redirects": [{"status": 302, "location": "//cdn.example.test/v1/export"}],
  "sig": "<base64url hmac>"
}
```

- `method`: case-sensitive string. It is signed as written.
- `url`: the initial request URL, signed **exactly** as this string.
  Do not normalize, lowercase, or add a default port before verifying.
- `body_sha256`: lowercase hex digest the caller claims for the body.
  This lab does not open a body file. The signature binds this claim.
- `redirects`: recorded hop list, in order. Follow every entry up to
  `max_hops`. Status is informational; do not filter on 301/302/307.
- `sig`: base64url (no `=` padding) of HMAC-SHA256 over the signing input.

There is no live HTTP client. Do not connect, and do not call the
system resolver (`getaddrinfo`, `socket`, or similar).

## Signing input (normative)

ASCII, fields joined by `|` with **no** spaces:

```
{method}|{url}|{body_sha256}
```

`url` is the raw `plan["url"]`, not a redirect target and not a
normalized form. HMAC key material is `policy.sig_secret` (hex-decoded
when the secret is valid hex, otherwise UTF-8 bytes). Compare with
`hmac.compare_digest`.

When `require_sig` is false, skip this gate. When it is true, a
missing or mismatched `sig` is `bad_signature`. Check the signature
**only after every hop has passed**. A hop failure keeps that hop's
reason; do not replace it with `bad_signature`, and do not allow
just because the signature matches.

## Resolver snapshot

```json
{"answers": {"api.example.test": ["93.184.216.34"]}}
```

Lookup key: hostname lowercased, trailing dots removed. The fixture
names are already in that form.

- Missing key, or an empty address list → `nxdomain`.
- An address that is not a valid IP → raise (CLI exit 2).
- Every address is kept. Order is the snapshot order. Checking only
  the first address is non-compliant.
- IP-literal hosts are **not** looked up in the snapshot. See below.

## Pin store

```json
{"pins": {"api.example.test": ["93.184.216.34"]}}
```

Keys use the same hostname normalization. Compare addresses with
`ipaddress` (so spelling variants of the same IP match), not with a
raw substring.

`policy.pin_mode`:

- `strict`: the host key must already exist, and **every** resolved
  address must be a member of that list. Otherwise `pin_mismatch`.
  Never add keys.
- `first_seen`: if the host key is absent, remember this request's
  addresses as a candidate pin. If the key exists, the same subset
  rule as `strict` applies — a new address for a known host is
  `pin_mismatch`, not an append. Candidates are written back only
  when the **whole chain** allows. Any deny discards every candidate
  from this call. Persist canonical compressed text
  (`str(ipaddress.ip_address(...))`), sorted ascending.
  Within one call, the first observation of a host is the candidate;
  a later hop for that same host must fit that candidate.

The library mutates the `pin_store` dict in place. The CLI atomically
writes that dict (temp file, then replace) after `admit_request`
returns. Deny and load failure must not grow `pins`.

## Addresses that must not be contacted

`blocked_cidrs` is the only block list. Do not substitute a shorter
private-range guess.

```
0.0.0.0/8
10.0.0.0/8
100.64.0.0/10
127.0.0.0/8
169.254.0.0/16
172.16.0.0/12
192.0.0.0/24
192.0.2.0/24
192.168.0.0/16
198.18.0.0/15
198.51.100.0/24
203.0.113.0/24
224.0.0.0/4
240.0.0.0/4
::/128
::1/128
fc00::/7
fe80::/10
2001:db8::/32
ff00::/8
```

`169.254.169.254` is covered by `169.254.0.0/16` (link-local,
including the well-known metadata address). No separate hostname
blacklist.

If an address is IPv4-mapped IPv6 (`::ffff:a.b.c.d`), test the outer
IPv6 address **and** the embedded IPv4 address against this list.
A mapped address is blocked when the embedded IPv4 is blocked, even
if the IPv6 form hits none of the IPv6 prefixes.

An address in a blocked range is `blocked_ip` even when that exact
address is already in the pin store.

## IP literals

A host is an IP literal when `ipaddress.ip_address` accepts the
hostname (`127.0.0.1`, or `::1` taken from `[::1]`). Decimal, octal,
and hex host tricks are out of scope; those stay ordinary hostnames
and use the snapshot.

When `forbid_ip_literal` is true, an IP-literal host is `blocked_ip`
**before** snapshot lookup. This still applies when the literal is a
public address that happens to equal some other host's pin. When the
flag is false, the literal is the sole resolved address (no snapshot
lookup) and still goes through the CIDR and pin gates.

## Scheme, port, userinfo

- Scheme comes from the URL parser, compared case-insensitively to
  `allowed_schemes`. Anything else, or a URL with no hostname, is
  `scheme_denied`.
- If the URL authority contains userinfo (`user@host`,
  `user:password@host`, or a netloc that contains `@`), the hop is
  `userinfo_forbidden`. Do not strip the userinfo and continue.
- Missing port uses `default_ports` for the scheme. The effective
  port must be a member of `allowed_ports`, else `port_denied`.
  An explicit default (`:443` on https) is fine when 443 is allowed.

## Redirects

Walk `plan.redirects` in order. Hop 0 is `plan.url`. Redirect *i*
(0-based) is applied only when *i* < `max_hops` and every previous
hop passed. Otherwise the decision is `redirect_limit` and that
location is not evaluated.

Join `location` onto the current hop URL with `urllib.parse.urljoin`.
That covers absolute URLs, path-absolute URLs, and protocol-relative
locations that start with `//`. Each joined URL is a new hop and
repeats scheme, userinfo, literal, snapshot, CIDR, pin, port, and
path checks. A first hop that would have been allowed does not excuse
a later hop.

## Path and host group

Policy path is the URL path only (query and fragment are ignored).
An empty path is `/`.

1. If any `denied_path_substrings` entry occurs inside that path,
   `path_denied`. Do not scan the whole URL or the hostname.
2. Otherwise the host's group must have a matching `path_allow`
   entry. `exact` is equality. `prefix` is literal
   `path.startswith(prefix)`. Entries for other groups do not count.
   A prefix is not a substring search: `/evil/v1/export` does not
   match prefix `/v1/`. No match → `path_denied`.

A host belongs to at most one group in these fixtures. A host in no
group has no allow entry.

## Gate order (each hop)

Apply in this order, first failure wins:

1. `scheme_denied`
2. `userinfo_forbidden`
3. `blocked_ip` for an IP literal when `forbid_ip_literal` is true
4. `nxdomain`
5. `blocked_ip` for a resolved address in `blocked_cidrs`
   (including IPv4-mapped embedded IPv4)
6. `pin_mismatch`
7. `port_denied`
8. `path_denied` (denied substring, then group-scoped allow)
9. next redirect, or `redirect_limit` when the next index is past
   `max_hops`

After the initial URL and every followed redirect pass, if
`require_sig` is true, verify the signature. Failure is
`bad_signature`.

## Reason codes

Exact strings: `scheme_denied`, `userinfo_forbidden`, `blocked_ip`,
`nxdomain`, `pin_mismatch`, `port_denied`, `path_denied`,
`redirect_limit`, `bad_signature`.

On deny, `reason_codes` contains that one string. On allow it is
empty. Report shape: `docs/report-schema.md`.

## Forbidden shortcuts

- Allowing because the HMAC matches while a hop is private, unpinned,
  literal, or not in the snapshot.
- Reading only the first snapshot address.
- Checking only `plan.url` and ignoring later hops.
- Stripping userinfo and admitting the rest.
- Treating a public IP literal as safe because it is not a private
  range or because it equals some pin.
- Calling live DNS when the snapshot has no answer.
- Treating `path_allow` as a substring of the whole URL, or applying
  one group's prefix to a host in another group.
- Skipping `denied_path_substrings` once a prefix matches.
- Writing `first_seen` pins before the full chain allows, or writing
  them on deny.
- Signing a normalized URL instead of the raw `plan["url"]`.
