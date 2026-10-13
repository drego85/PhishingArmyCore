# Phishing Army contributor instructions

These rules are architectural invariants, not optional style preferences.

- Prioritize low false positives over maximum coverage.
- Treat every generation as a fresh snapshot. Do not retain or silently carry forward indicators.
- The explicitly declared harmless test domain `amiprotected.it` is a local exception, not upstream phishing data. It must respect personal allowlisting and never satisfy source-health or publication-size guards.
- Never promote an arbitrary tenant hostname to its parent. Only an exact relative `www` subdomain may add its registrable domain.
- Never block a shared hosting, dynamic DNS or shortener root solely because one tenant or path is malicious.
- Preserve the precedence of `personal_whitelist.txt` and add regression tests for every whitelist-policy change.
- Keep both legacy output filenames and make them identical to the canonical balanced domain feed.
- Render every format from one canonical domain set; do not add format-specific indicators.
- Isolate source failures, use bounded retries, respect rate limits and refuse unsafe publication.
- Never commit, print or log tokens. Treat `Config.py` as secret and keep `Config.sample.py` empty.
- Keep output deterministic and atomically replaced; install the manifest last.
- Do not change production cron jobs or publish feeds from development tooling.
- Test in a temporary output directory and compare shadow builds with the public list before rollout.
- Document source window, authentication, filters, attribution and exclusion decisions in `SOURCES.md`.
- Always describe Phishing Army as an aggregator and clearly credit every active data provider in the repository, generated feeds and project website.
- Never obscure source provenance. Phishing Army's added value is balanced aggregation, normalization, false-positive reduction, format generation and reliable distribution.
