# php2shell-scanner

A command-line tool for detecting CVE-2026-109618 and CVE-2026-109619 in PHP applications.

## How It Works

The scanner sends a minimal multipart control request followed by up to three crafted multipart probes. The probes use PHP array keys nested 62 levels deep and increase from 1 MiB to 20 MiB, matching the detection logic used by Assetnote's internal scanner.

A target is reported vulnerable when the probe produces a PHP memory-exhaustion error, a differential empty HTTP 500, a PHP-FPM worker failure, or an advertised PHP version known to be unpatched. Initial 5xx responses, common request-rejection statuses, and nonempty HTTP 500 responses without the PHP fatal-error signature are not treated as crash signals.

The scanner tests `/index.php` by default. A path supplied in the URL is preserved, and `--path` or `--path-file` can test custom paths. phpMyAdmin targets are automatically retested at `/show_config_errors.php`. Redirects are not followed.

### SAPI Modes

The default `--sapi auto` mode applies both mod_php and PHP-FPM verdict rules, matching the combined behavior of Assetnote's postmodules. Use `--sapi mod_php` or `--sapi fpm` to restrict detection to a known SAPI.

### Network Impact

Each tested path may receive a 42-byte control request and three probes totalling about 29 MiB. Probing stops as soon as the verdict is settled, and duplicate input URLs are scanned once.

## Wildcard Subdomain Scanning

Targets written in `*.domain.com` style are expanded into the apex domain plus every known subdomain, and each resulting host is scanned:

```
python3 scanner.py -u "*.example.com"
```

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

## Usage

Scan a single host:

```
python3 scanner.py -u https://example.com
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

Results are printed to the terminal. When using `-o`, vulnerable hosts are saved to a JSON file with the verdict reason and redacted HTTP request/response evidence.

## Limitations

On specific PHP configurations, the scanner may report a false positive when its multipart probe exceeds PHP's `memory_limit`. Patched and vulnerable versions can then return the same empty HTTP 500 response.

This was reproduced on patched PHP 8.4.27 with `memory_limit` values from **2M to 32M**, and on PHP 8.3.36 at **128M** when `max_multipart_body_parts` is set to **2785 or higher**. The exact threshold may vary between builds.

When PHP does not disclose its version, the scanner cannot distinguish this safe post-patch OOM from the vulnerable pre-patch behavior. Results should therefore be verified against the installed PHP version and any vendor backports
