# Phishing Army Core

Phishing Army is a transparent aggregator of independent phishing intelligence sources. It generates a current, balanced domain blocklist and intentionally favours a low false-positive rate over blocking the largest possible number of domains.

The value added by Phishing Army is not the concealment or republishing of third-party work. It is the careful selection of suitable live feeds, normalization, conservative domain expansion, shared-platform handling, whitelist policy, deduplication, format generation and reliable distribution. Every data provider must be clearly acknowledged in this repository and on the project website.

The public service is available at [phishing.army](https://phishing.army/) and serves more than one million users. This repository contains the feed generator; it does not retain a historical indicator database.

## Protection policy

Every build starts from the live snapshot exposed by each source. A phishing indicator disappears from Phishing Army when it is no longer present in any current source. The deliberately harmless test domain described below is an explicit local exception, not historical phishing data.

- The observed hostname is blocked after normalization and whitelist checks.
- A `www` hostname also promotes its registrable domain. Other subdomains are never promoted automatically.
- Trusted namespaces are protected at the root and below it.
- URL shorteners such as `bit.ly` are not blocked because path-level abuse cannot be represented safely in a DNS list.
- Shared hosting and dynamic DNS roots such as `no-ip.com` are protected, while an explicitly observed tenant such as `phishing.no-ip.com` can be blocked.
- `list/personal_whitelist.txt` has the highest precedence.
- A parent is suppressed when a broad rule would override a specifically allowed descendant.

The Public Suffix List bundled with `tldextract` is used offline, including private suffixes. Private suffix boundaries are automatically treated as shared platforms, so a popular service root cannot whitelist every tenant. An explicitly ranked tenant protects only its own namespace. Explicit exceptions for shared services not represented by the PSL live in `list/shared_subdomain_services.txt` and `list/path_shared_services.txt`.

## Harmless filtering test

`amiprotected.it` is an operator-owned, harmless static website. The apex and `www.amiprotected.it` are deliberately added to the canonical domain set on every build. Neither hostname is phishing or attributed to an upstream provider, and neither must be submitted to those providers as a real threat. Visit <https://amiprotected.it/> to check whether your configured consumer blocks the test domain; a reachable page is not an assessment of overall security, and a connection failure alone does not identify which filter caused it.

Both hostnames appear in all seven formats and both identical legacy files. Every generated banner explicitly identifies them as harmless tests, and the manifest lists them separately in `test_domains`. Provider counts and `raw_indicators` do not include the local tests. Lookup exposes them under `local_test_domains`, separately from upstream matches.

Popularity-based whitelisting cannot silently disable these dedicated tests. The operator-controlled personal whitelist retains precedence. Explicitly allowing the apex suppresses both hostnames; allowing a descendant suppresses any broader test rule that would override it. Exact-host consumers can test either the apex or `www` once HTTPS is configured for that hostname.

The tests do not count as a healthy source or towards the minimum-size and previous-size publication guards. A failed or collapsed provider snapshot still refuses publication. Nothing about these explicit test exceptions changes the fresh-snapshot policy for real phishing indicators.

## Install and configure

Python 3.11 or newer is recommended.
Production generation uses a POSIX file lock (Linux or macOS). All four policy files in `list/` must exist; missing files refuse generation rather than disabling false-positive protection.

```bash
python3 -m venv venv
venv/bin/pip install -r requirements.txt
cp Config.sample.py Config.py
```

Set API credentials and the output directory in the ignored `Config.py`. Credentials are transmitted only as required by each provider: most authenticated sources use headers, PhishTank embeds its application key in the download path, and URLAbuse requires the registered email and token as request parameters. Secret values and their URL-encoded representations are redacted from source errors.

## Commands

Generate all feeds:

```bash
venv/bin/python phishing.py build
```

Generate into a safe staging directory:

```bash
venv/bin/python phishing.py build --output /tmp/phishing-army-shadow
```

Test all sources and publication guards without writing output files:

```bash
venv/bin/python phishing.py build --dry-run
```

Search a domain in the current live source snapshots:

```bash
venv/bin/python phishing.py lookup pincopallo.com
```

The lookup is intentionally live and may differ from the last published build.

## Output formats

All output formats contain the same balanced domain set:

| File | Intended use |
| --- | --- |
| `phishing-army-domains.txt` | One domain per line; canonical format |
| `phishing-army-adblock.txt` | Adblock/ABP-compatible DNS rules |
| `phishing-army-hosts.txt` | Hosts-file consumers |
| `phishing-army-dnsmasq.conf` | DNSMasq configuration |
| `phishing-army-wildcard.txt` | Asterisk wildcard consumers |
| `phishing-army-unbound.conf` | Unbound local zones |
| `phishing-army-rpz.zone` | Response Policy Zone consumers |
| `phishing-army-manifest.json` | Counts, source health, timings and SHA-256 hashes |

The legacy files `phishing_army_blocklist.txt` and `phishing_army_blocklist_extended.txt` remain available and are byte-for-byte identical to the canonical domain feed.

Files are rendered deterministically and replaced atomically. Publication is refused when every source fails, when fewer than 100 domains are produced, or when a candidate is below 25% of the previous published size. The manifest is installed last.
Scheduled and manual `build` executions use a persistent `.phishing-army-build.lock` in the output directory to prevent overlap. Keep that lock file in place; its lock is released automatically when the process exits.

The canonical indicators are identical across formats, but matching semantics differ: hosts files are exact-host entries, while Adblock, DNSMasq, Unbound and RPZ rules also cover descendants. Plain-domain and wildcard consumers apply their own matching rules. Resolver configuration files require validation, loading and periodic refresh by the consuming system.

## Three-hour staging comparison

Before production rollout, run a shadow build every three hours for several days and compare it with the current public extended list:

```bash
venv/bin/python phishing.py build --output /tmp/phishing-army-shadow
venv/bin/python phishing.py compare /tmp/phishing-army-shadow/phishing-army-domains.txt
```

Store the JSON output from `compare` in an operational log if a time series is needed. Phishing Army itself does not retain indicator history. The production cron schedule can then move from six to three hours; cron configuration remains an operator action and is not changed by this repository.

## Whitelist maintenance

Whitelist refresh is manual, normally monthly:

```bash
venv/bin/python phishing.py whitelist-candidate
```

This downloads the standard Tranco Top 1M list, records its permanent ID and SHA-256, merges the maintained business list and the three anudeepND allowlists, and creates `list/global_whitelist.candidate.txt` plus metadata. Candidate roots that would hide indicators in the current public blocklist are excluded unless they are recognized shared-platform boundaries. The command never overwrites `global_whitelist.txt`; review the added and removed domains first.

The approved local whitelist now uses Tranco list `4672X`, generated and adopted on 12 October 2026. Its inputs and SHA-256 are recorded in `list/global_whitelist.metadata.json`. The earlier 2022 whitelist has been replaced. Future refreshes remain manual and require a comparison before adoption.

## Development

```bash
venv/bin/python -m unittest discover -s tests -v
```

Architecture and invariants are documented in [docs/architecture.md](docs/architecture.md). Active and excluded feeds are documented in [SOURCES.md](SOURCES.md).

## Usage and support

Phishing Army was created primarily for personal and individual protection and its generated feeds remain freely accessible. Anyone can support continued development, generation, hosting and distribution through [Buy Me a Coffee](https://www.buymeacoffee.com/andreadraghetti). Contributions from individual users are always welcome, while organizations and commercial users that benefit from the feeds are especially encouraged to provide voluntary recurring support.

The generator source code is licensed under the [GNU General Public License v3.0](LICENSE). Each upstream provider retains its own rights and may apply separate conditions to commercial use, redistribution or automation. Organizations are solely responsible for reviewing every source's terms and obtaining any authorization required for their use case. Phishing Army cannot sublicense third-party data. Support is voluntary and does not purchase access, upstream licensing rights, priority support, an SLA or endorsement. See [Usage and licensing](https://phishing.army/license/) for the plain-language notice.
