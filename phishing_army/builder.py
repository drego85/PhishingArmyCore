from __future__ import annotations

import logging
from dataclasses import dataclass, field

from .config import Settings
from .domain import WhitelistPolicy, balanced_domains, normalize_domain
from .http import HttpClient
from .sources import Source, SourceResult, active_sources


TEST_DOMAINS = frozenset({"amiprotected.it", "www.amiprotected.it"})


@dataclass
class BuildResult:
    domains: set[str]
    sources: list[SourceResult]
    raw_indicators: int
    test_domains: set[str] = field(default_factory=set)

    @property
    def successful_sources(self) -> int:
        return sum(result.status == "ok" for result in self.sources)

    @property
    def failed_sources(self) -> int:
        return sum(result.status == "failed" for result in self.sources)


def build(
    settings: Settings,
    policy: WhitelistPolicy,
    sources: list[Source] | None = None,
    client: HttpClient | None = None,
) -> BuildResult:
    selected = sources if sources is not None else active_sources()
    http = client or HttpClient()
    raw: set[str] = set()
    results: list[SourceResult] = []
    for source in selected:
        result = source.fetch(http, settings)
        results.append(result)
        if result.status == "ok":
            raw.update(result.indicators)
            logging.info(
                "Source %s returned %d indicators in %.2fs",
                result.name,
                len(result.indicators),
                result.duration_seconds,
            )
        else:
            logging.warning("Source %s %s: %s", result.name, result.status, result.error)
    # This operator-owned, harmless indicator is not upstream phishing data.
    # Popularity rankings must not disable the test; explicit personal policy
    # still wins, including protection of an allowed descendant.
    test_policy = WhitelistPolicy(set(), policy.personal_domains, set(), set())
    test_domains = balanced_domains(set(TEST_DOMAINS), test_policy)
    domains = balanced_domains(raw, policy) | test_domains
    return BuildResult(domains, results, len(raw), test_domains)


def live_lookup(query: str, result: BuildResult) -> list[tuple[str, list[str]]]:
    target = normalize_domain(query)
    if not target:
        raise ValueError(f"Invalid domain or URL: {query}")
    matches: list[tuple[str, list[str]]] = []
    for source in result.sources:
        found: set[str] = set()
        for indicator in source.indicators:
            parts = normalize_domain(indicator)
            if parts and (
                parts.fqdn == target.fqdn
                or parts.registered == target.fqdn
                or parts.fqdn.endswith(f".{target.fqdn}")
            ):
                found.add(parts.fqdn)
        if found:
            matches.append((source.name, sorted(found)))
    return matches
