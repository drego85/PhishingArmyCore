# Release preparation: 13 October 2026

## Implemented corrections

- Malformed URL authorities and IDNA failures are discarded without cancelling healthy source indicators.
- The four required policy files must exist before generation starts.
- Whitelist candidates and their metadata cannot target active policy files, including through symlinks. Candidate files and metadata are replaced atomically with readable permissions.
- API adapters distinguish valid empty responses from errors or unexpected schemas. PhishTank validates its CSV columns.
- URLAbuse makes a single attempt per generation; failures are retried by the next scheduled generation.
- A POSIX lock serializes scheduled and manual builds in each output directory.
- Allowed descendants suppress broad parent indicators. A ranked tenant protects its own namespace without authorizing unrelated tenants.
- Requests 2.34.2 and urllib3 2.8.0 replace the older HTTP packages. OSV returned no advisories for these two versions at the time of verification.
- The website now explains matching semantics, credits whitelist inputs, improves code contrast and scrolls linked FAQ answers after the accordion transition.

## Approved Tranco whitelist

The active whitelist is now based on Tranco list `4672X`, with 999,685 normalized entries after maintained additions and conflict filtering. 345 conflicts with the current public blocklist were excluded. Inputs, approval time and hashes are in `list/global_whitelist.metadata.json`. The personal whitelist was unchanged during that adoption on 12 October. On 13 October, reviewed exceptions were added for `link.me`, the Hoxhunt training domains `authentication.ms` and `security.email-microsoft.com`, and the FTC-referenced Amazon refund domain `subscriptionmembershipsettlement.com`, with regression coverage.

A single live source snapshot was evaluated using both the 2022 whitelist and Tranco, keeping source turnover out of the comparison:

| Metric | 2022 whitelist | Tranco whitelist |
| --- | ---: | ---: |
| Canonical domains | 156,796 | 156,916 |
| In common with public feed | 141,263 | 141,263 |
| Local only | 15,533 | 15,653 |
| Public only | 161 | 161 |

The whitelist change added 139 hostnames and excluded 19. All nine sources completed successfully. Google Search Ads domains, vk.ru, hub.la and shared platform roots remain protected. Generation remains a fresh snapshot and all output formats use one canonical set.

## Validation and remaining work

The regression suite now covers malformed indicators in mixed-source builds, missing policies, active-file overwrite protection, ranked tenants, protected descendants, source schemas, rate limits and concurrent build locking. Generated hashes and legacy equality are checked; the generated Unbound configuration passes `unbound-checkconf`. The website compiles and the updated FAQ scroll and contrast were checked in Chrome's iPhone SE viewport.

The stable Eleventy dependency tree still has advisories involving braces 3.0.3 and sprintf-js, including dependent packages. The compatible dependency refresh fixed js-yaml and brace-expansion advisory ranges. No patched compatible stable braces or sprintf-js versions were available; npm's suggested forced downgrade is inappropriate. This is a local development/build-tool concern, not a Node runtime deployed to the static hosting. See the Web README for the remaining constraints and recheck before future updates.

No production feed, hosting configuration or cron was changed. Before rollout, save the intended changes in both Git repositories, update the production Python environment, generate the new formats on the production server and then upload the static website while preserving `/download/`. The six-hour to three-hour cron change remains an operator action.

The operator has registered and brought `amiprotected.it` online. Core now deliberately adds both the harmless filtering-test apex and `www.amiprotected.it` to each canonical snapshot, with separate manifest/lookup provenance and explanatory banners. Neither counts towards provider health or publication-size guards; personal whitelist precedence remains unchanged. Before rollout, publish a healthy generation through the normal operator workflow and verify real consumers against the HTTPS apex and, once its certificate is ready, the `www` hostname. The website wording tests configured filtering rather than promising protection from all phishing.

The current local suite passes 56 regression tests, including checks for both test hostnames in every output format, both legacy files and the newly reviewed whitelist exceptions. `pip check` reports no broken requirements. The 999,685-entry Tranco file matches its recorded SHA-256. No configured API tokens were found in the candidate repository files, and every configuration value in `Config.sample.py` is empty. `.gitignore` is included in the release so credentials, logs, virtual environments and whitelist candidates remain excluded in fresh checkouts.

A packaging correction scopes the private configuration ignore rule to `/Config.py`. The earlier unanchored rule also ignored `phishing_army/config.py` on the case-insensitive development filesystem, leaving the internal module out of the first release commit. The internal module is now tracked. CLI startup and all 56 regression tests pass from a clean tracked-file export without the operator's private `Config.py`; this check is now required by the contributor instructions.

A temporary live build generated at 08:12:28 UTC on 13 October 2026 completed with all nine providers healthy, 197,895 distinct raw indicators and 159,925 canonical domains. It includes both harmless test hostnames and the seven reviewed shared-platform boundaries; the new personal-whitelist exceptions are absent. Manifest hashes were verified, the two legacy files are byte-for-byte identical to the canonical feed, and the output is ASCII. The generated Unbound include passed `unbound-checkconf` with local test settings for username, chroot and pidfile, without starting a resolver.

Comparison at 08:12:49 UTC found 140,844 common entries, 19,081 candidate-only entries and 237 public-only entries; the public feed had 141,081 entries. Six public-only entries are suppressed by the current whitelist policy. The remaining 231 are absent from the local snapshot, but comparison alone cannot distinguish changes in live source contents from differences in collection. These are separate snapshots, not a controlled comparison of old and new generators against identical source data. No production files or cron configuration were changed.

The HTTPS apex returned 200 with a valid certificate and `Cache-Control: no-store` on 12 October 2026. A fresh check on 13 October still found that the certificate for `www.amiprotected.it` does not match that hostname; the operator is arranging it. A TLS error must not be mistaken for working filtering.
