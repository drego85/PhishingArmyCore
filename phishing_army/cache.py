from __future__ import annotations

import re

import requests

from .config import Settings
from .http import HttpClient
from .output import LEGACY_FILES, RENDERERS


FEED_BASE_URL = "https://phishing.army/download/"


def purge_cloudflare(
    settings: Settings, manifest: dict, client: HttpClient | None = None,
) -> dict:
    """Invalidate only known public feed URLs, without exposing API credentials."""
    if not settings.cloudflare_token and not settings.cloudflare_zone_id:
        return {"status": "disabled"}
    if not settings.cloudflare_token or not re.fullmatch(
        r"[0-9a-f]{32}", settings.cloudflare_zone_id
    ):
        return {"status": "failed", "error": "Missing token or invalid Cloudflare zone ID"}
    expected = set(RENDERERS) | set(LEGACY_FILES)
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != expected:
        return {"status": "failed", "error": "Unexpected publication manifest files"}
    urls = [FEED_BASE_URL + name for name in sorted(expected)]
    urls.append(FEED_BASE_URL + "phishing-army-manifest.json")
    http = client or HttpClient(timeout=20, attempts=3)
    try:
        response = http.post(
            f"https://api.cloudflare.com/client/v4/zones/{settings.cloudflare_zone_id}/purge_cache",
            headers={"Authorization": f"Bearer {settings.cloudflare_token}"},
            json={"files": urls},
            allow_redirects=False,
        )
        if response.status_code != 200:
            return {"status": "failed", "error": f"HTTP {response.status_code}"}
        payload = response.json()
        if not isinstance(payload, dict) or payload.get("success") is not True:
            return {"status": "failed", "error": "Cloudflare rejected the cache purge"}
    except requests.RequestException as error:
        # Never log exception strings or provider messages: either may echo a token.
        status = error.response.status_code if error.response is not None else None
        return {
            "status": "failed",
            "error": f"HTTP {status}" if status else "Cloudflare request failed",
        }
    except ValueError:
        return {"status": "failed", "error": "Invalid Cloudflare API response"}
    return {"status": "ok", "urls": len(urls)}
