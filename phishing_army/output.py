from __future__ import annotations

import hashlib
import fcntl
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from contextlib import contextmanager

from .builder import TEST_DOMAINS, BuildResult


LEGACY_FILES = (
    "phishing_army_blocklist.txt",
    "phishing_army_blocklist_extended.txt",
)


@contextmanager
def generation_lock(output_directory: Path):
    """Prevent a scheduled or manual build from racing another publisher."""
    output_directory.mkdir(parents=True, exist_ok=True)
    # Keep the lock inode in place: unlinking it would allow a second lock.
    with (output_directory / ".phishing-army-build.lock").open("a") as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("another Phishing Army generation is already running") from None
        try:
            yield
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)


def _banner(
    prefix: str, generated: str, count: int, format_name: str,
    test_domains: list[str],
) -> str:
    test_notice = (
        "This test domain is intentionally included; it is not a phishing report."
        if len(test_domains) == 1 else
        "These test domains are intentionally included; they are not phishing reports."
    )
    lines = [
        "",
        "Title: Phishing Army | Community phishing domain blocklist",
        "Aggregated from independent phishing intelligence sources.",
        "Sources: PhishTank, OpenPhish, CERT.PL, Phishunt, urlscan.io, PhishStats,",
        "StalkPhish, URLAbuse and AntiPhish.org.",
        "",
        "Expires: 1 day",
        f"Generated: {generated}",
        f"Entries: {count}",
        f"Format: {format_name}; version=1",
        *(
            [
                f"Harmless filtering test: {', '.join(test_domains)}",
                test_notice,
            ]
            if test_domains else []
        ),
        "",
        "Policy: balanced protection with a focus on low false positives.",
        "Shared hosting and dynamic DNS platforms are not blocked wholesale.",
        "",
        "Homepage: https://phishing.army/",
        "Report false positives: drego85@draghetti.it",
        "",
        "Free for personal and individual use.",
        "Anyone may support the project with a donation, tip or recurring contribution.",
        "Individual support is always welcome. Organizations and commercial users",
        "that benefit from the feeds are especially encouraged to contribute.",
        "Support is voluntary and funds development, feed generation, hosting and distribution.",
        "Commercial users are responsible for upstream source terms and for",
        "obtaining any permissions required for their own use case.",
        "Support: https://www.buymeacoffee.com/andreadraghetti",
        "Usage and licensing: https://phishing.army/license/",
        "",
        "Data sources, acknowledgements and usage information:",
        "https://github.com/drego85/PhishingArmyCore/blob/master/SOURCES.md",
        "======================================================================",
    ]
    return "\n".join(f"{prefix} {line}".rstrip() for line in lines) + "\n\n"


def _line_renderer(prefix: str, name: str, line: Callable[[str], str]):
    def render(domains: list[str], generated: str) -> str:
        test_domains = sorted(set(domains) & TEST_DOMAINS)
        return _banner(prefix, generated, len(domains), name, test_domains) + "".join(
            f"{line(domain)}\n" for domain in domains
        )

    return render


def _render_rpz(domains: list[str], generated: str) -> str:
    serial = int(datetime.fromisoformat(generated.replace("Z", "+00:00")).timestamp())
    header = _banner(";", generated, len(domains), "RPZ", sorted(set(domains) & TEST_DOMAINS))
    zone = (
        "$TTL 60\n"
        "@ IN SOA localhost. hostmaster.localhost. "
        f"{serial} 3600 600 86400 60\n"
        "@ IN NS localhost.\n"
    )
    records = "".join(
        f"{domain} CNAME .\n*.{domain} CNAME .\n" for domain in domains
    )
    return header + zone + records


def _render_unbound(domains: list[str], generated: str) -> str:
    header = _banner("#", generated, len(domains), "Unbound", sorted(set(domains) & TEST_DOMAINS))
    records = "".join(
        f'    local-zone: "{domain}." always_nxdomain\n' for domain in domains
    )
    return header + "server:\n" + records


RENDERERS = {
    "phishing-army-domains.txt": _line_renderer("#", "domains", lambda d: d),
    "phishing-army-adblock.txt": _line_renderer("!", "Adblock", lambda d: f"||{d}^"),
    "phishing-army-hosts.txt": _line_renderer("#", "hosts", lambda d: f"0.0.0.0 {d}"),
    "phishing-army-dnsmasq.conf": _line_renderer("#", "DNSMasq", lambda d: f"local=/{d}/"),
    "phishing-army-wildcard.txt": _line_renderer("#", "wildcard-asterisk", lambda d: f"*.{d}"),
    "phishing-army-unbound.conf": _render_unbound,
    "phishing-army-rpz.zone": _render_rpz,
}


def count_existing_entries(
    path: Path, excluded_domains: frozenset[str] = frozenset(),
) -> int:
    if not path.exists():
        return 0
    with path.open(encoding="utf-8", errors="replace") as stream:
        return sum(
            1
            for line in stream
            if line.strip()
            and not line.lstrip().startswith(("#", "!", ";"))
            and line.strip() not in excluded_domains
        )


def validate_publish(
    result: BuildResult,
    output_directory: Path,
    minimum_entries: int = 100,
    minimum_previous_ratio: float = 0.25,
) -> None:
    if result.successful_sources == 0:
        raise RuntimeError("publication refused: no source completed successfully")
    source_entries = len(result.domains - TEST_DOMAINS)
    if source_entries < minimum_entries:
        raise RuntimeError(
            f"publication refused: only {source_entries} source-derived entries "
            f"(minimum {minimum_entries})"
        )
    previous = count_existing_entries(output_directory / LEGACY_FILES[1], TEST_DOMAINS)
    if previous and source_entries < int(previous * minimum_previous_ratio):
        raise RuntimeError(
            "publication refused: candidate is less than "
            f"{minimum_previous_ratio:.0%} of previous source-derived list "
            f"({source_entries} vs {previous})"
        )


def publish(
    result: BuildResult,
    output_directory: Path,
    *,
    dry_run: bool = False,
    minimum_entries: int = 100,
    minimum_previous_ratio: float = 0.25,
) -> dict:
    output_directory.mkdir(parents=True, exist_ok=True)
    validate_publish(result, output_directory, minimum_entries, minimum_previous_ratio)
    domains = sorted(result.domains)
    generated = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    canonical = RENDERERS["phishing-army-domains.txt"](domains, generated)
    rendered = {name: renderer(domains, generated) for name, renderer in RENDERERS.items()}
    rendered.update({name: canonical for name in LEGACY_FILES})

    files = {
        name: {
            "bytes": len(content.encode("utf-8")),
            "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
        }
        for name, content in sorted(rendered.items())
    }
    manifest = {
        "schema_version": 1,
        "generated_at": generated,
        "entries": len(domains),
        "raw_indicators": result.raw_indicators,
        "test_domains": sorted(set(domains) & TEST_DOMAINS),
        "sources": [
            {
                "name": item.name,
                "status": item.status,
                "indicators": len(item.indicators),
                "duration_seconds": round(item.duration_seconds, 3),
                **({"error": item.error} if item.error else {}),
            }
            for item in result.sources
        ],
        "files": files,
    }
    if dry_run:
        return manifest

    temporary_paths: dict[str, Path] = {}
    try:
        for name, content in rendered.items():
            descriptor, temporary = tempfile.mkstemp(
                prefix=f".{name}.", dir=output_directory, text=True
            )
            path = Path(temporary)
            temporary_paths[name] = path
            os.fchmod(descriptor, 0o644)
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
        for name, path in temporary_paths.items():
            os.replace(path, output_directory / name)
        temporary_paths.clear()

        descriptor, temporary = tempfile.mkstemp(
            prefix=".phishing-army-manifest.json.", dir=output_directory, text=True
        )
        temporary_paths["phishing-army-manifest.json"] = Path(temporary)
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(manifest, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output_directory / "phishing-army-manifest.json")
        temporary_paths.clear()
    finally:
        for path in temporary_paths.values():
            path.unlink(missing_ok=True)
    return manifest
