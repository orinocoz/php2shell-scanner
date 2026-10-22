# php2shell-scanner

A command-line tool for detecting CVE-2026-109618 and CVE-2026-109619 in PHP applications.

## How It Works

The scanner sends a minimal multipart control request followed by up to three crafted multipart probes. The probes use PHP array keys nested 62 levels deep and increase from 1 MiB to 20 MiB, matching the detection logic used by Assetnote's internal scanner.

A target is reported vulnerable when the probe produces a PHP memory-exhaustion error, a differential empty HTTP 500, a PHP-FPM worker failure, or an advertised PHP version known to be unpatched. Initial 5xx responses, common request-rejection statuses, and nonempty HTTP 500 responses without the PHP fatal-error signature are not treated as crash signals.

The scanner tests `/index.php` by default. A path supplied in the URL is preserved, and `--path` or `--path-file` can test custom paths. phpMyAdmin targets are automatically retested at `/show_config_errors.php`. Redirects are not followed.

### Directory Listing Discovery

When the tested path answers with a directory listing (Apache/nginx autoindex, detected by an `Index of` title or heading), the scanner does not probe the listing itself. Instead it extracts every `.php` link (up to 10, relative and absolute, same host only) and runs the control request plus probes against each file, reporting the best verdict found. A listing that links no `.php` files is reported as `NO SIGNAL` with an explicit reason instead of burning probes.

Servers that reject `POST` to a static directory with `405`/`501` are handled: the scanner re-fetches the path with `GET` and uses that listing. Discovered paths are recorded in the JSON output under `discovered_paths`, and verdict reasons note that the endpoint was `found via directory listing at <url>`.

### SAPI Modes

The default `--sapi auto` mode applies both mod_php and PHP-FPM verdict rules, matching the combined behavior of Assetnote's postmodules. Use `--sapi mod_php` or `--sapi fpm` to restrict detection to a known SAPI.

### Network Impact

Each tested path may receive a 42-byte control request and three probes totalling about 29 MiB. A directory listing instead costs one control request (or one `GET` when `POST` is refused) plus up to ten discovered `.php` files tested as normal paths. Probing stops as soon as the verdict is settled, and duplicate input URLs are scanned once.

## Wildcard Subdomain Scanning

Targets written in `*.domain.com` style are expanded into the apex domain plus every known subdomain, and each resulting host is scanned:

```
python3 scanner.py -u "*.example.com"
```

A full step-by-step guide for wildcard scanning with DNSDumpster (getting a key, configuring it, examples, and troubleshooting) is in [docs/wildcard-dnsdumpster.md](docs/wildcard-dnsdumpster.md).

Two discovery sources are available, controlled with `--subdomain-source`:

- `dnsdumpster` — the official DNSDumpster API (`https://api.dnsdumpster.com/domain/<domain>`). Needs an API key, which is free at [dnsdumpster.com](https://dnsdumpster.com/membership/); supply it with `--dnsdumpster-key` or the `DNSDUMPSTER_API_KEY` environment variable. Free keys return up to 50 records per domain; Plus keys return up to 200 per page and pagination is followed automatically. The API is rate limited to one request every 2 seconds, which the scanner observes.
- `crtsh` — certificate transparency logs via [crt.sh](https://crt.sh/). Needs no API key and no signup, but only finds subdomains that have appeared on TLS certificates.
- `auto` (default) — uses DNSDumpster when an API key is available, otherwise falls back to crt.sh.

Details:

- The apex domain (for example `example.com`) is always scanned alongside the discovered subdomains.
- Wildcards work in `-l` list files too, mixed freely with regular hosts.
- `http://*.example.com` or `*.example.com:8080` apply that scheme or port to every discovered host; the default is `https` on the standard port.
- Only real web subdomains are kept: wildcard entries and underscore records such as `_dmarc` or `_sip._tcp` are skipped, as are hosts outside the requested domain.
- Discovered host lists are recorded in the JSON output under `wildcard_expansions` when `-o` is used.
- When discovery fails for a pattern (for example a rate limit), the scanner reports it and continues with the remaining targets.

## Requirements

- Python 3.9+
- h11
- tqdm

## Installation

```
pip install -r requirements.txt
```

## Docker

Build the image from the project directory:

```sh
docker build -t php2shell-scanner .
```

Scan a host and test a custom path:

```sh
docker run --rm php2shell-scanner -u https://example.com --path /admin.php
```

Test multiple paths by repeating `--path`:

```sh
docker run --rm php2shell-scanner -u https://example.com \
  --path /index.php --path /admin.php
```

To use local input and output files, mount the current directory at `/work`:

```sh
docker run --rm -v "$PWD:/work" -w /work php2shell-scanner \
  -l hosts.txt -t 20 -o results.json --path /index.php --path /admin.php
```

For `--path-file`, put the file in the mounted directory and refer to it by its
container path:

```sh
docker run --rm -v "$PWD:/work" -w /work php2shell-scanner \
  -u https://example.com --path-file /work/paths.txt
```

For wildcard scans using DNSDumpster, pass the API key through an environment
variable:

```sh
docker run --rm -e DNSDUMPSTER_API_KEY \
  php2shell-scanner -u '*.example.com' --subdomain-source dnsdumpster
```

## Usage

Scan a single host:

```
python3 scanner.py -u https://example.com
```

The URL may include a path, with or without a trailing slash. That exact path
is scanned (instead of the default `/index.php`):

```
python3 scanner.py -u https://example.com/path
python3 scanner.py -u https://example.com/path/
```

Scan a list of hosts:

```
python3 scanner.py -l hosts.txt
```

Scan every known subdomain for a domain (plus the apex domain), no API key needed:

```
python3 scanner.py -u "*.example.com"
python3 scanner.py -l hosts.txt   # hosts.txt may contain *.domain.com lines
```

Prefer DNSDumpster results by providing an API key:

```
export DNSDUMPSTER_API_KEY=your_free_key
python3 scanner.py -u "*.example.com" --subdomain-source dnsdumpster
```

Scan with multiple threads and save results:

```
python3 scanner.py -l hosts.txt -t 20 -o results.json
```

Scan with custom headers:

```
python3 scanner.py -u https://example.com -H "Authorization: Bearer token" -H "Cookie: session=abc"
```

Scan a custom path:

```
python3 scanner.py -u https://example.com --path /phpinfo.php
python3 scanner.py -u https://example.com --path /index.php --path /admin.php
python3 scanner.py -u https://example.com --path-file paths.txt
```

Use a URL path such as `https://example.com/path/` to scan that path directly.
The `--path` option overrides the URL path and can be repeated to test several
paths.

Use only PHP-FPM verdict rules:

```
python3 scanner.py -u https://example.com --sapi fpm
```

## Options

```
-u, --url         Single URL to check ('*.domain.com' expands all subdomains)
-l, --list        File containing hosts (one per line; '*.domain.com' lines expand)
-t, --threads     Number of concurrent threads (default: 10)
--timeout         Request timeout in seconds (default: 60)
-o, --output      Output file for results (JSON)
--all-results     Save all results, not just vulnerable hosts
-k, --insecure    Disable TLS certificate verification
-H, --header      Custom header (can be used multiple times)
-v, --verbose     Show verdict reasons and response snippets
-q, --quiet       Only output vulnerable hosts
--no-color        Disable colored output
--sapi            Verdict rules: auto, mod_php, or fpm (default: auto)
--path            Custom path to test (can be used multiple times)
--path-file       File containing paths to test (one per line)
--dnsdumpster-key API key for the DNSDumpster subdomain source
                  (default: $DNSDUMPSTER_API_KEY)
--subdomain-source Where '*.domain.com' subdomains come from:
                  auto, dnsdumpster, or crtsh (default: auto)
```

## Credits

The first, original discovery of php2shell is attributed to the Calif team. You can read their write up here: [https://calif.io/php2shell/](https://calif.io/php2shell/).

The scanner was built by the Assetnote Security Research Team using logic built for [Searchlight's Exposure Platform](https://www.slcyber.io/exposure).

## Output

Results are printed to the terminal. When using `-o`, vulnerable hosts are saved to a JSON file with the verdict reason and redacted HTTP request/response evidence; add `--all-results` to keep every verdict.

### Verdicts

| Verdict | Meaning | Trust it? |
| --- | --- | --- |
| `VULNERABLE` | A crash signal matched, or `X-Powered-By` advertises an unpatched PHP release | Yes |
| `FIXED` | No crash and `X-Powered-By` advertises a patched release | Yes |
| `NO SIGNAL` | No crash, but the server does not advertise its PHP version | **Not proof of safety** — the probes ran clean, but without a version header the scanner cannot confirm the running PHP is patched; verify the version manually or expose `X-Powered-By` |
| `INCONCLUSIVE` | The target responded, but the verdict could not be established (probes rejected by a proxy/WAF, the endpoint already returned 5xx, the connection dropped mid-upload) | No — the probes never reached PHP or the result is ambiguous |
| `ERROR` | The target was never tested (DNS, TLS, timeout, connection failure) | No — nothing was tested |

`-v` prints the reason for every verdict, and INCONCLUSIVE/ERROR reasons are shown even without it.

### Scan summary

After the scan the summary lists every tested endpoint grouped by outcome, so you can see which host is at risk and how much to trust each verdict — not just counts:

```
============================================================
SCAN SUMMARY
============================================================
  Total hosts scanned: 6
  Vulnerable: 1
  Not vulnerable: 2
    verified patched (X-Powered-By): 1
    NO SIGNAL - version unknown, NOT proof of safety: 1
  Inconclusive/errors: 3
    tls: 2
    dns: 1

AT RISK - VULNERABLE (1)
    http://…/files/ — found via directory listing at http://…/files/: probe 1 …

CONFIRMED PATCHED - X-Powered-By advertises a fixed release (1)
    http://…/clean.php — no crash observed and X-Powered-By reports a patched r…

NO SIGNAL - probes ran clean but the PHP version is unknown; verify manually (1)
    http://…/empty/ — the target is a directory listing and links no .php files…

INCONCLUSIVE - target answered in a way the probes cannot judge (0)
    (none)

ERROR - the check never completed (3)
    https://…/index.php — dns: control request failed: [Errno -2] Name or…
============================================================
```

Every group prints the per-host verdict reason (truncated to the terminal width; the full text is in the JSON). The vulnerable group is never truncated; other groups list up to 15 hosts and point to `-o results.json` beyond that. `Inconclusive/errors` also breaks the failures down by `error_category`, so a timeout-heavy scan (your network) reads differently from a `request_rejected`-heavy one (a WAF in front of the target).

### Error categories

Transport failures carry an `error_category` in the JSON (`result.error_category`, and per-request in the `control` and `probes` objects), together with a plain-language explanation of what happened and what to do next:

| Category | Meaning |
| --- | --- |
| `dns` | The hostname does not resolve; the target was never contacted |
| `tls` | TLS handshake or certificate verification failed (try `-k` for self-signed certificates) |
| `timeout` | No response within `--timeout` seconds |
| `connection` | Connection refused or a network error while connecting |
| `protocol` | The peer sent malformed or incomplete HTTP (a proxy or portal may be intercepting) |
| `transport` | The HTTP exchange was interrupted mid-response |
| `request` | The request could not be encoded for this target |
| `unknown` | Unexpected failure; please report it |

Rejections before PHP parsed the probes use `request_rejected`, and an already-failing endpoint uses `server_error`.

### Triage with jq

```bash
python3 scanner.py -l hosts.txt -o results.json --all-results

# Summary by verdict
jq -r '.results | group_by(.verdict)[] | "\(.[0].verdict): \(length)"' results.json

# Host + verdict + reason for everything that is not a confirmed clean result
jq -r '.results[] | select(.verdict != "FIXED") | "\(.verdict)\t\(.host)\t\(.reason // .error)"' results.json

# Group the untestable hosts by failure cause
jq -r '.results[] | select(.error_category != null) | .error_category' results.json | sort | uniq -c
```

## Limitations

On specific PHP configurations, the scanner may report a false positive when its multipart probe exceeds PHP's `memory_limit`. Patched and vulnerable versions can then return the same empty HTTP 500 response.

This was reproduced on patched PHP 8.4.27 with `memory_limit` values from **2M to 32M**, and on PHP 8.3.36 at **128M** when `max_multipart_body_parts` is set to **2785 or higher**. The exact threshold may vary between builds.

When PHP does not disclose its version, the scanner cannot distinguish this safe post-patch OOM from the vulnerable pre-patch behavior. Results should therefore be verified against the installed PHP version and any vendor backports
