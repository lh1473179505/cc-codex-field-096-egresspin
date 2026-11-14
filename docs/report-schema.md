# report schema

`inspect` prints only the parsed plan. It does not resolve, pin, or
follow redirects:

```json
{
  "method": "GET",
  "scheme": "https",
  "host": "api.example.test",
  "port": 443,
  "path": "/healthz",
  "redirects": []
}
```

`host` is the parsed hostname (no userinfo, no brackets). `port` is
the explicit port or the scheme default (https 443, http 80). `path`
is `/` when the URL has an empty path. `redirects` is the raw plan
list.

`admit` writes:

```json
{
  "decision": "allow",
  "reason_codes": [],
  "method": "GET",
  "final_url": "https://api.example.test/healthz",
  "scheme": "https",
  "host": "api.example.test",
  "port": 443,
  "path": "/healthz",
  "resolved_ips": ["93.184.216.34"],
  "hops": [
    {
      "url": "https://api.example.test/healthz",
      "scheme": "https",
      "host": "api.example.test",
      "port": 443,
      "path": "/healthz",
      "resolved_ips": ["93.184.216.34"]
    }
  ],
  "notes": []
}
```

Top-level `final_url`, `scheme`, `host`, `port`, `path`, and
`resolved_ips` describe the hop that decided the result: the last hop
on allow, the failing hop on deny. `hops` lists every hop that was
evaluated, including the failing one, and omits a redirect that was
not evaluated because of `redirect_limit`.

For a followed redirect, `hops[].url` is the urljoin result, not the
raw `location`. `resolved_ips` is `[]` when that hop failed before
resolution (scheme, userinfo, forbidden IP literal, nxdomain). When
resolution happened, preserve snapshot order. `notes` may be empty.
`reason_codes` is empty on allow and a single reason code on deny.
