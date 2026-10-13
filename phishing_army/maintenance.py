from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from .domain import WhitelistPolicy, load_domain_file, normalize_domain
from .http import HttpClient


PUBLIC_LIST_URL = "https://phishing.army/download/phishing_army_blocklist_extended.txt"
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
TRANCO_ID_URL = "https://tranco-list.eu/top-1m-id"
ANUDEEP_URLS = (
    "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt",
    "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/referral-sites.txt",
    "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/optional-list.txt",
)


def parse_domain_list(text: str) -> set[str]:
    domains: set[str] = set()
    for line in text.splitlines():
        value = line.strip()
        if not value or value.startswith(("#", "!", ";")):
            continue
        if value.startswith("||") and value.endswith("^"):
            value = value[2:-1]
        elif " " in value:
            value = value.split()[-1]
        parsed = normalize_domain(value)
        if parsed:
            domains.add(parsed.fqdn)
    return domains


def compare_with_public(candidate: Path, client: HttpClient | None = None) -> dict:
    local = parse_domain_list(candidate.read_text(encoding="utf-8"))
    public = parse_domain_list((client or HttpClient()).get(PUBLIC_LIST_URL).text)
    return {
        "compared_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "candidate_file": str(candidate),
        "candidate_entries": len(local),
        "public_entries": len(public),
        "common_entries": len(local & public),
        "candidate_only": len(local - public),
        "public_only": len(public - local),
        "jaccard_similarity": round(len(local & public) / len(local | public), 6)
        if local or public
        else 1.0,
    }


def _registered(value: str) -> str | None:
    parsed = normalize_domain(value)
    return parsed.registered if parsed else None


def _candidate_conflicts(
    domains: set[str], current_blocks: set[str], shared_roots: set[str]
) -> set[str]:
    """Find candidate roots that would hide current non-shared indicators."""
    conflicts: set[str] = set()
    for blocked in current_blocks:
        parsed = normalize_domain(blocked)
        if not parsed:
            continue
        shared = next(
            (root for root in WhitelistPolicy._ancestors(parsed.fqdn)
             if root in shared_roots),
            parsed.private_suffix,
        )
        for root in WhitelistPolicy._ancestors(blocked):
            if root not in domains:
                continue
            # A ranking at or above a tenant boundary does not allow tenants.
            # Ranking the tenant itself (or a descendant namespace below the
            # boundary) still conflicts with an observed blocked hostname.
            if shared and (root == shared or shared.endswith(f".{root}")):
                continue
            conflicts.add(root)
    return conflicts


def generate_whitelist_candidate(
    list_directory: Path,
    destination: Path | None = None,
    client: HttpClient | None = None,
) -> dict:
    destination = destination or list_directory / "global_whitelist.candidate.txt"
    metadata_path = destination.with_suffix(destination.suffix + ".metadata.json")
    protected = {
        (list_directory / name).resolve()
        for name in (
            "global_whitelist.txt", "personal_whitelist.txt",
            "shared_subdomain_services.txt", "path_shared_services.txt",
            "business_domains.txt",
        )
    }
    if any(path.resolve() in protected for path in (destination, metadata_path)):
        raise ValueError("Whitelist candidate must not overwrite an active policy file")
    http = client or HttpClient(timeout=120)
    zip_response = http.get(TRANCO_URL)
    tranco_id = http.get(TRANCO_ID_URL).text.strip()
    domains: set[str] = set()
    with zipfile.ZipFile(io.BytesIO(zip_response.content)) as archive:
        csv_names = [name for name in archive.namelist() if name.endswith(".csv")]
        if not csv_names:
            raise RuntimeError("Tranco archive contains no CSV file")
        with archive.open(csv_names[0]) as raw:
            stream = io.TextIOWrapper(raw, encoding="utf-8")
            for row in csv.reader(stream):
                if len(row) >= 2:
                    domain = _registered(row[1])
                    if domain:
                        domains.add(domain)

    business_path = list_directory / "business_domains.txt"
    if business_path.exists():
        for line in business_path.read_text(encoding="utf-8").splitlines():
            domain = _registered(line)
            if domain:
                domains.add(domain)
    for url in ANUDEEP_URLS:
        for line in http.get(url).text.splitlines():
            domain = _registered(line)
            if domain:
                domains.add(domain)

    current_blocks = parse_domain_list(http.get(PUBLIC_LIST_URL).text)
    shared_roots = load_domain_file(list_directory / "shared_subdomain_services.txt")
    conflicts = _candidate_conflicts(domains, current_blocks, shared_roots)
    domains.difference_update(conflicts)

    approved = load_domain_file(list_directory / "global_whitelist.txt")
    destination.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(f"{domain}\n" for domain in sorted(domains))
    descriptor, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        Path(temporary).unlink(missing_ok=True)
    metadata = {
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "tranco_id": tranco_id,
        "tranco_url": TRANCO_URL,
        "tranco_archive_sha256": hashlib.sha256(zip_response.content).hexdigest(),
        "candidate_entries": len(domains),
        "approved_entries": len(approved),
        "added": len(domains - approved),
        "removed": len(approved - domains),
        "excluded_current_blocklist_conflicts": len(conflicts),
        "conflict_reference_url": PUBLIC_LIST_URL,
        "candidate_file": str(destination),
    }
    descriptor, temporary = tempfile.mkstemp(prefix=f".{metadata_path.name}.", dir=destination.parent)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(metadata, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, metadata_path)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return metadata
