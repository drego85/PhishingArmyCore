from __future__ import annotations

import csv
import gzip
import io
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable
from urllib.parse import quote_plus

from .config import Settings
from .http import HttpClient


@dataclass
class SourceResult:
    name: str
    indicators: set[str] = field(default_factory=set)
    status: str = "ok"
    error: str | None = None
    duration_seconds: float = 0.0


class Source:
    def __init__(
        self,
        name: str,
        fetcher: Callable[[HttpClient, Settings], Iterable[str]],
        requires: str | tuple[str, ...] | None = None,
    ) -> None:
        self.name = name
        self.fetcher = fetcher
        self.requires = requires

    def fetch(self, client: HttpClient, settings: Settings) -> SourceResult:
        started = time.monotonic()
        required = (
            (self.requires,)
            if isinstance(self.requires, str)
            else self.requires or ()
        )
        missing = [name for name in required if not getattr(settings, name)]
        if missing:
            return SourceResult(
                self.name,
                status="skipped",
                error=f"missing configuration: {', '.join(missing)}",
                duration_seconds=time.monotonic() - started,
            )
        try:
            values = {value.strip() for value in self.fetcher(client, settings) if value.strip()}
            return SourceResult(
                self.name,
                indicators=values,
                duration_seconds=time.monotonic() - started,
            )
        except Exception as error:  # Source isolation is intentional.
            message = f"{type(error).__name__}: {error}"
            for secret in (
                settings.phishtank_token,
                settings.stalkphish_token,
                settings.urlscan_token,
                settings.urlabuse_email,
                settings.urlabuse_token,
            ):
                if secret:
                    for representation in (secret, quote_plus(secret)):
                        message = message.replace(representation, "[redacted]")
            return SourceResult(
                self.name,
                status="failed",
                error=message,
                duration_seconds=time.monotonic() - started,
            )


def _text_lines(client: HttpClient, url: str) -> Iterable[str]:
    response = client.get(url)
    return (line.strip() for line in response.text.splitlines() if line.strip())


def _api_records(payload: object, keys: tuple[str, ...], source: str) -> list[dict]:
    """Accept a valid empty feed, but never hide an API error or schema change."""
    if isinstance(payload, dict):
        if payload.get("success") is False or payload.get("error"):
            raise RuntimeError(f"{source} returned an API error")
        for key in keys:
            if key in payload:
                payload = payload[key]
                break
        else:
            raise RuntimeError(f"{source} returned an unexpected API response")
    if not isinstance(payload, list):
        raise RuntimeError(f"{source} records must be a list")
    return [record for record in payload if isinstance(record, dict)]


def fetch_phishtank(client: HttpClient, settings: Settings) -> Iterable[str]:
    response = client.get(
        f"https://data.phishtank.com/data/{settings.phishtank_token}/online-valid.csv.gz",
        headers={"User-Agent": "phishtank/phishingarmy"},
    )
    compressed = io.BytesIO(response.content)
    binary_stream = (
        gzip.GzipFile(fileobj=compressed)
        if response.content.startswith(b"\x1f\x8b")
        else compressed
    )
    with io.TextIOWrapper(binary_stream, encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if not {"url", "verified", "online"}.issubset(reader.fieldnames or ()):
            raise RuntimeError("PhishTank returned an unexpected CSV schema")
        for record in reader:
            if (
                str(record.get("verified", "")).lower() == "yes"
                and str(record.get("online", "")).lower() == "yes"
                and record.get("url")
            ):
                yield str(record["url"])


def fetch_openphish(client: HttpClient, settings: Settings) -> Iterable[str]:
    return _text_lines(
        client,
        "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
    )


def fetch_certpl(client: HttpClient, settings: Settings) -> Iterable[str]:
    return _text_lines(client, "https://hole.cert.pl/domains/v2/domains.txt")


def fetch_phishunt(client: HttpClient, settings: Settings) -> Iterable[str]:
    return _text_lines(client, "https://phishunt.io/feed.txt")


def fetch_urlscan(client: HttpClient, settings: Settings) -> Iterable[str]:
    response = client.get(
        "https://urlscan.io/api/v1/search/",
        headers={"API-Key": settings.urlscan_token},
        params={
            "q": 'task.visibility:"public" AND task.tags:("phishing" OR "malicious") AND page.status:200',
            "size": 1000,
            "datasource": "scans",
        },
    )
    for record in _api_records(response.json(), ("results",), "urlscan.io"):
        task = record.get("task")
        value = task.get("url") if isinstance(task, dict) else None
        if value:
            yield str(value)


def fetch_phishstats(client: HttpClient, settings: Settings) -> Iterable[str]:
    response = client.get(
        "https://api.phishstats.info/api/phishing",
        params={"_sort": "-id", "_p": 0, "_size": 100},
    )
    records = _api_records(response.json(), ("data",), "PhishStats")
    for record in records:
        if isinstance(record, dict) and record.get("url"):
            yield str(record["url"])


def fetch_stalkphish(client: HttpClient, settings: Settings) -> Iterable[str]:
    response = client.get(
        "https://api.stalkphish.io/api/v1/last",
        headers={"Authorization": f"Token {settings.stalkphish_token}"},
    )
    records = _api_records(response.json(), ("results",), "StalkPhish")
    for record in records:
        if not isinstance(record, dict):
            continue
        value = record.get("siteurl") or record.get("sitedomain")
        if value:
            yield str(value)


def fetch_urlabuse(client: HttpClient, settings: Settings) -> Iterable[str]:
    response = client.get(
        "https://urlabuse.com/get_record_by_rowid",
        # URLAbuse asks for five minutes between calls. Retry next generation.
        attempts=1,
        params={
            "email": settings.urlabuse_email,
            "token": settings.urlabuse_token,
        },
    )
    payload = response.json()
    if not isinstance(payload, dict) or payload.get("success") is not True:
        message = (
            payload.get("msg", "invalid API response")
            if isinstance(payload, dict)
            else "invalid API response"
        )
        raise RuntimeError(f"URLAbuse API error: {message}")
    records = payload.get("attr")
    if not isinstance(records, list):
        raise RuntimeError("URLAbuse API error: attr is not a list")
    for record in records:
        if not isinstance(record, dict):
            continue
        if str(record.get("rtype", "")).strip().lower() != "phishing":
            continue
        value = record.get("url")
        if value:
            yield str(value)


def _antiphish_records(payload: object) -> list[dict]:
    return _api_records(payload, ("data", "results", "items"), "AntiPhish.org")


def fetch_antiphish(client: HttpClient, settings: Settings) -> Iterable[str]:
    response = client.get("https://api.antiphish.org/v1/search")
    for record in _antiphish_records(response.json()):
        if str(record.get("threat_type", "")).lower() != "phishing":
            continue
        value = (
            record.get("host")
            or record.get("url")
            or record.get("page_url")
            or record.get("page")
        )
        if value:
            yield str(value)


def active_sources() -> list[Source]:
    return [
        Source("PhishTank", fetch_phishtank, "phishtank_token"),
        Source("OpenPhish", fetch_openphish),
        Source("CERT.PL", fetch_certpl),
        Source("Phishunt", fetch_phishunt),
        Source("urlscan.io", fetch_urlscan, "urlscan_token"),
        Source("PhishStats", fetch_phishstats),
        Source("StalkPhish", fetch_stalkphish, "stalkphish_token"),
        Source(
            "URLAbuse",
            fetch_urlabuse,
            ("urlabuse_email", "urlabuse_token"),
        ),
        Source("AntiPhish.org", fetch_antiphish),
    ]
