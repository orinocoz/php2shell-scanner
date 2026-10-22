# Wildcard Subdomain Scanning with DNSDumpster

This guide explains how to scan every known subdomain of a domain in one
command, using the DNSDumpster API for discovery.

## What it does

A target written as `*.domain.com` is expanded before scanning:

1. The scanner queries the DNSDumpster API for every subdomain DNSDumpster
   knows about `domain.com`.
2. It keeps only real web subdomains (see [Filtering rules](#filtering-rules)).
3. It builds the target list: the apex domain first (`domain.com`), then every
   discovered subdomain (`www.domain.com`, `mail.domain.com`, ...).
4. Each resulting host is scanned with the normal php2shell probes, using the
   configured thread pool.

You get one result summary and one JSON file for the whole domain, instead of
maintaining a subdomain list by hand.

## Prerequisites

- A DNSDumpster API key. Keys are free at
  [dnsdumpster.com/membership](https://dnsdumpster.com/membership/); sign up,
  then copy the key shown on your membership page.
- The scanner dependencies installed (`pip install -r requirements.txt`).

Key tiers, as they affect scanning:

| Key tier | Records per domain | Pagination |
| --- | --- | --- |
| Free | up to 50 | single page |
| Plus | up to 200 per page | up to 10 pages, followed automatically |

## Configuring the API key

Either export the key before running:

```bash
export DNSDUMPSTER_API_KEY=your_free_key
python3 scanner.py -u "*.example.com" --subdomain-source dnsdumpster
```

or pass it per run:

```bash
python3 scanner.py -u "*.example.com" \
  --subdomain-source dnsdumpster \
  --dnsdumpster-key your_free_key
```

`--dnsdumpster-key` takes precedence over the environment variable.

If you request `--subdomain-source dnsdumpster` without a key, the scanner
exits with:

```
The DNSDumpster subdomain source requires an API key.
Pass --dnsdumpster-key KEY or set the DNSDUMPSTER_API_KEY environment variable (free keys: https://dnsdumpster.com/membership/),
or use --subdomain-source crtsh to discover subdomains without a key.
```

Tip: put the key in your shell profile or a secrets manager rather than
passing `--dnsdumpster-key` on the command line, so it does not land in your
shell history or process list.

## Choosing the discovery source

`--subdomain-source` accepts:

| Value | Behavior |
| --- | --- |
| `auto` (default) | DNSDumpster when a key is available (flag or env var), otherwise crt.sh |
| `dnsdumpster` | Always DNSDumpster; requires a key |
| `crtsh` | Always crt.sh certificate transparency logs; no key needed |

With `auto` and no key, the scanner prints:

```
[*] No DNSDumpster API key found; discovering subdomains via crt.sh (certificate transparency)
```

Use `dnsdumpster` explicitly when you want DNS results (it typically finds
more live hosts than certificate logs, which only cover hosts that had TLS
certificates).

## Usage examples

### Single domain, DNSDumpster

```bash
export DNSDUMPSTER_API_KEY=your_free_key
python3 scanner.py -u "*.example.com" --subdomain-source dnsdumpster
```

Progress output:

```
[*] Querying DNSDumpster for example.com ...
[+] *.example.com: 14 subdomain(s) found via DNSDumpster plus the apex domain example.com
[*] Loaded 15 host(s) to scan
...
```

### Non-HTTPS or non-standard port

The scheme and port you write are applied to every discovered host:

```bash
# Scan all subdomains over plain HTTP on port 8080
python3 scanner.py -u "http://*.example.com:8080" --subdomain-source dnsdumpster
```

This produces targets like `http://www.example.com:8080`. Without an explicit
scheme the scanner uses `https` on the standard port.

### Multiple domains and mixed lists

Wildcard patterns work in `-l` list files, mixed freely with regular hosts:

Create a `targets.txt` file:

```text
# targets.txt
*.example.com
*.example.org
https://standalone-host.com
```

```bash
python3 scanner.py -l targets.txt --subdomain-source dnsdumpster -t 20
```

Duplicate patterns (case-insensitive) are scanned once; the same subdomain
found for two patterns is also deduplicated.

### Combine with other options

Everything composes with the normal flags:

```bash
export DNSDUMPSTER_API_KEY=your_free_key

# Save every verdict (not only vulnerable hosts) to JSON
python3 scanner.py -u "*.example.com" --subdomain-source dnsdumpster \
  -o results.json --all-results -v

# Test custom PHP entry points on every discovered host
python3 scanner.py -u "*.example.com" --subdomain-source dnsdumpster \
  --path /index.php --path /admin.php

# Only print vulnerable hosts, TLS errors tolerated
python3 scanner.py -u "*.example.com" --subdomain-source dnsdumpster -q -k
```

## Output

### Terminal

Besides the per-host verdict lines, wildcard runs report what was expanded:

```
[*] Loaded 15 host(s) to scan
[*] Expanded 1 wildcard pattern(s) into 15 host(s) via DNSDumpster
[*] Skipped 2 duplicate host(s)
```

### JSON

With `-o file.json`, the output includes a `wildcard_expansions` object
mapping each pattern to the exact hosts it produced:

```json
{
  "scan_time": "2026-10-22T12:00:00Z",
  "total_results": 1,
  "wildcard_expansions": {
    "*.example.com": [
      "example.com",
      "www.example.com",
      "mail.example.com",
      "api.staging.example.com",
      "blog.example.com"
    ]
  },
  "results": [ { "host": "www.example.com", "verdict": "VULNERABLE", "...": "..." } ]
}
```

By default only vulnerable hosts appear in `results`; add `--all-results` to
keep every verdict (FIXED, NO SIGNAL, INCONCLUSIVE, ERROR).

## How discovery works

- The scanner calls `https://api.dnsdumpster.com/domain/<domain>` with your
  key in the `X-API-Key` header.
- Requests are rate limited to one every 2 seconds, which matches the API
  limit; the scanner waits rather than failing.
- Free keys return a single page. If a Plus key is configured, pagination
  follows up to 10 pages (or 2000 records) per domain; pagination stops
  quietly when a page requires a higher membership tier.
- The apex domain is always included in the scan, whether or not DNSDumpster
  lists it.

### Filtering rules

Discovered names are normalized (lowercased, trailing dot removed) and then
filtered. A name is kept only if it:

- ends with `.<your-domain>` — results outside the requested domain are
  dropped;
- contains no `*` — wildcard DNS entries never answer HTTP;
- contains no `_` — underscore records (`_dmarc`, `_sip._tcp`) are not web
  hosts;
- is not a duplicate (first occurrence wins, original order is preserved).

Everything is IDNA-encoded, so internationalized domains are handled.

## Failure modes

| Situation | Behavior |
| --- | --- |
| API key missing with `--subdomain-source dnsdumpster` | Scanner exits with an explanatory error |
| API rate limit (HTTP 429) | Reported as an error for that pattern; other patterns continue |
| API error / bad key (HTTP 4xx) | Reported as an error for that pattern; other patterns continue |
| Network failure reaching DNSDumpster | Reported as an error for that pattern; other patterns continue |
| All patterns fail (nothing to scan) | Scanner exits: `Wildcard expansion failed: <errors>` |
| One pattern fails, others succeed | Scan continues with the successful expansions |

When a pattern fails but others succeed, the scan proceeds; the failure is
printed as a warning (`[!] *.example.com: DNSDumpster API request failed ...`)
so re-run the failed domains afterwards.

## DNSDumpster vs crt.sh

| | DNSDumpster | crt.sh |
| --- | --- | --- |
| API key | required (free tier available) | not needed |
| Data source | DNS records | certificate transparency logs |
| Typical coverage | more live hosts | only hosts that had TLS certs |
| Rate limits | 1 request / 2 s | polite spacing, 1 request / 1 s |

For authorized exposure scanning of your own domains, DNSDumpster is the
better default when you can get a key; crt.sh is the zero-signup fallback.

## See also

- [README.md](../README.md) — installation, full option list, and how the
  php2shell probes work
