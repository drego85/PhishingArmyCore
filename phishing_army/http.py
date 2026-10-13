from __future__ import annotations

import email.utils
import logging
import time
from datetime import datetime, timezone
from typing import Any

import requests


class HttpClient:
    def __init__(self, timeout: int = 60, attempts: int = 3) -> None:
        self.timeout = timeout
        self.attempts = attempts
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "PhishingArmy/2.0 (+https://phishing.army/)",
                "Accept": "application/json, text/plain, */*",
            }
        )

    @staticmethod
    def _retry_delay(response: requests.Response | None, attempt: int) -> float:
        if response is not None and response.status_code == 429:
            raw = response.headers.get("Retry-After", "")
            try:
                return max(0.0, float(raw))
            except ValueError:
                try:
                    target = email.utils.parsedate_to_datetime(raw)
                    return max(0.0, (target - datetime.now(timezone.utc)).total_seconds())
                except (TypeError, ValueError):
                    return 30.0
        return float(2 ** attempt)

    def get(
        self, url: str, *, attempts: int | None = None, **kwargs: Any
    ) -> requests.Response:
        return self._request("get", url, attempts=attempts, **kwargs)

    def post(
        self, url: str, *, attempts: int | None = None, **kwargs: Any
    ) -> requests.Response:
        return self._request("post", url, attempts=attempts, **kwargs)

    def _request(
        self, method: str, url: str, *, attempts: int | None = None, **kwargs: Any
    ) -> requests.Response:
        attempt_limit = self.attempts if attempts is None else attempts
        if attempt_limit < 1:
            raise ValueError("HTTP attempts must be at least one")
        last_error: Exception | None = None
        for attempt in range(attempt_limit):
            response: requests.Response | None = None
            try:
                response = getattr(self.session, method)(url, timeout=self.timeout, **kwargs)
                if response.status_code not in (429, 500, 502, 503, 504):
                    response.raise_for_status()
                    return response
                last_error = requests.HTTPError(
                    f"HTTP {response.status_code} from {response.url}", response=response
                )
            except requests.RequestException as error:
                last_error = error

            if attempt + 1 >= attempt_limit:
                break
            delay = self._retry_delay(response, attempt)
            # A daily quota must fail this source, not stall the entire build.
            if delay > 60:
                break
            logging.warning("Temporary HTTP failure; retrying in %.1fs", delay)
            time.sleep(delay)
        assert last_error is not None
        raise last_error
