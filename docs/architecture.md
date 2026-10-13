# Architecture

The generator is a stateless pipeline:

1. Fetch every enabled live source independently with bounded retries.
2. Normalize URLs and domains to lowercase IDNA hostnames using an offline Public Suffix List snapshot.
3. Apply the layered whitelist and shared-platform policy.
4. Add the registrable domain only when the observed relative subdomain is exactly `www`.
5. Add the explicitly declared harmless filtering test, respecting personal whitelist precedence, then deduplicate and sort the single canonical domain set.
6. Render every static format from that set.
7. Validate minimum-size and previous-size guards, atomically replace files, then install the manifest last.

Source failures are visible in logs and the manifest but do not abort healthy sources. A total failure, empty/small list or major unexplained size collapse blocks publication.

`amiprotected.it` and `www.amiprotected.it` are deliberately harmless local test indicators. They are rebuilt from the explicit `TEST_DOMAINS` declaration on every run, not retained from a previous snapshot and not supplied by an upstream phishing provider. Popularity whitelists cannot disable them, while explicit personal whitelisting still can. They are included in the canonical domain set for all renderers, labelled in banners and listed in the manifest. Source-success counts, raw-indicator counts and both publication-size guards exclude their contribution. Lookup identifies them separately from live provider matches.

Malformed indicators are discarded during normalization. All four policy files must exist before a build can fetch or publish anything. A parent indicator is suppressed if its broad descendants rule would override a specifically allowed child. A shared platform root never authorizes all tenants; an explicitly ranked tenant protects only its own namespace.

The CLI holds a nonblocking POSIX file lock in the output directory throughout collection and publication, preventing simultaneous scheduled or manual builds from publishing interleaved artifacts. This serializes writers; atomic file replacement and the manifest-last rule still apply individually rather than as a whole-directory transaction.

An optional Cloudflare URL purge runs under that same lock after successful
default production publication. It targets only the known nine feed filenames
and their manifest on `phishing.army`. Dry runs and explicit staging outputs do
not trigger it. Failed purges are reported separately from successful disk
publication, with bounded retries and generic credential-safe errors. An
explicit `purge-cache` command retries this operation without collecting or
publishing indicators. Operational purge results are not written back into the
already installed public manifest.

There is no source-indicator database. `lookup` repeats the live fetch and reports which current sources contain the requested domain. `compare` is a quality-assurance operation whose JSON can be logged externally during a shadow rollout.

## Module map

- `phishing_army/sources.py`: provider adapters and source isolation.
- `phishing_army/http.py`: HTTP timeouts, retry and rate-limit handling.
- `phishing_army/cache.py`: optional targeted Cloudflare purge after publication.
- `phishing_army/domain.py`: normalization and whitelist policy.
- `phishing_army/builder.py`: aggregation and live lookup.
- `phishing_army/output.py`: renderers, guards, atomic publication and manifest.
- `phishing_army/maintenance.py`: public comparison and manual Tranco candidate generation.
- `phishing_army/cli.py`: operator interface.

`phishing.py` and `whitelist_generator.py` remain compatibility entry points.
