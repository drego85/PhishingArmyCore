from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit

import tldextract
import validators


_extract = tldextract.TLDExtract(
    cache_dir=None,
    suffix_list_urls=(),
    include_psl_private_domains=True,
)
_extract_public = tldextract.TLDExtract(
    cache_dir=None,
    suffix_list_urls=(),
    include_psl_private_domains=False,
)


@dataclass(frozen=True)
class DomainParts:
    fqdn: str
    registered: str
    subdomain: str
    private_suffix: str | None = None


def normalize_domain(value: str) -> DomainParts | None:
    """Extract and validate a DNS hostname from a URL or bare domain."""
    candidate = (value or "").strip()
    if not candidate or candidate.startswith(("#", "!", ";")):
        return None
    if candidate.lower().startswith("blob:"):
        candidate = candidate[5:]

    try:
        parsed = urlsplit(candidate if "://" in candidate else f"//{candidate}")
        host = parsed.hostname
    except ValueError:
        return None
    if not host:
        return None
    host = host.rstrip(".").lower()
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    try:
        ip_address(host)
        return None
    except ValueError:
        pass

    if not validators.domain(host):
        return None
    result = _extract(host)
    private_suffix = result.suffix if result.is_private else None
    registered = result.top_domain_under_public_suffix
    # A private suffix root (for example vercel.app) has no domain label in
    # the private-PSL view. Fall back to the ICANN view so the service root can
    # still participate in whitelist policy.
    if not registered and result.suffix:
        result = _extract_public(host)
        registered = result.top_domain_under_public_suffix
    if not registered or not result.suffix:
        return None
    return DomainParts(host, registered, result.subdomain, private_suffix)


def load_domain_file(path: Path, *, required: bool = False) -> set[str]:
    if not path.exists():
        if required:
            raise FileNotFoundError(f"Required policy file is missing: {path}")
        return set()
    domains: set[str] = set()
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            parsed = normalize_domain(line)
            if parsed:
                domains.add(parsed.fqdn)
    return domains


@dataclass
class WhitelistPolicy:
    global_domains: set[str]
    personal_domains: set[str]
    shared_subdomain_roots: set[str]
    path_shared_services: set[str]
    protected_parents: set[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        # A broad rule for a parent must never override an allowed descendant.
        self.protected_parents = {
            parent
            for domain in self.personal_domains | self.path_shared_services | self.global_domains
            for parent in list(self._ancestors(domain))[1:]
        }

    @classmethod
    def from_directory(cls, list_directory: Path) -> "WhitelistPolicy":
        return cls(
            load_domain_file(list_directory / "global_whitelist.txt", required=True),
            load_domain_file(list_directory / "personal_whitelist.txt", required=True),
            load_domain_file(list_directory / "shared_subdomain_services.txt", required=True),
            load_domain_file(list_directory / "path_shared_services.txt", required=True),
        )

    @staticmethod
    def _ancestors(domain: str):
        labels = domain.split(".")
        for index in range(max(0, len(labels) - 1)):
            yield ".".join(labels[index:])

    @classmethod
    def _has_namespace(cls, domain: str, roots: set[str]) -> bool:
        return any(candidate in roots for candidate in cls._ancestors(domain))

    def permits_blocking(self, parts: DomainParts) -> bool:
        if parts.fqdn in self.protected_parents:
            return False
        # The operator-controlled personal list deliberately has precedence.
        if self._has_namespace(parts.fqdn, self.personal_domains):
            return False
        if self._has_namespace(parts.fqdn, self.path_shared_services):
            return False

        # Protect the shared service itself, while allowing an exact tenant host.
        shared = next(
            (root for root in self._ancestors(parts.fqdn) if root in self.shared_subdomain_roots),
            None,
        )
        # Private PSL suffixes are tenant boundaries by definition. Treat them
        # as shared platforms even when Tranco contains the service root.
        if shared is None and parts.private_suffix:
            shared = parts.private_suffix
        if shared:
            if parts.fqdn == shared:
                return False
            # A popular platform root protects no tenants, but an explicitly
            # ranked tenant can still protect its own namespace.
            tenant_roots = (
                root for root in self._ancestors(parts.fqdn)
                if root.endswith(f".{shared}")
            )
            return not any(root in self.global_domains for root in tenant_roots)

        return not self._has_namespace(parts.fqdn, self.global_domains)


def balanced_domains(values: set[str], policy: WhitelistPolicy) -> set[str]:
    """Apply the low-false-positive policy and the conservative www promotion."""
    output: set[str] = set()
    for value in values:
        parts = normalize_domain(value)
        if not parts or not policy.permits_blocking(parts):
            continue
        output.add(parts.fqdn)
        if parts.subdomain == "www":
            apex = normalize_domain(parts.registered)
            if apex and policy.permits_blocking(apex):
                output.add(parts.registered)
    return output
