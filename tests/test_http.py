import unittest
from unittest.mock import Mock, patch

import requests

from phishing_army.http import HttpClient


class HttpTests(unittest.TestCase):
    def response(self, status, **headers):
        response = requests.Response()
        response.status_code = status
        response.url = "https://example.com/feed"
        response.headers.update(headers)
        return response

    def test_urlabuse_single_attempt_never_retries(self):
        client = HttpClient()
        client.session.get = Mock(return_value=self.response(503))
        with patch("phishing_army.http.time.sleep") as sleep:
            with self.assertRaises(requests.HTTPError):
                client.get("https://example.com/feed", attempts=1)
        client.session.get.assert_called_once()
        sleep.assert_not_called()
        self.assertNotIn("attempts", client.session.get.call_args.kwargs)

    def test_respects_retry_after_then_succeeds(self):
        client = HttpClient()
        client.session.get = Mock(side_effect=[
            self.response(429, **{"Retry-After": "7"}), self.response(200),
        ])
        with patch("phishing_army.http.time.sleep") as sleep:
            self.assertEqual(client.get("https://example.com/feed").status_code, 200)
        sleep.assert_called_once_with(7.0)

    def test_long_quota_reset_fails_without_stalling_build(self):
        client = HttpClient()
        client.session.get = Mock(return_value=self.response(429, **{"Retry-After": "3600"}))
        with patch("phishing_army.http.time.sleep") as sleep:
            with self.assertRaises(requests.HTTPError):
                client.get("https://example.com/feed")
        client.session.get.assert_called_once()
        sleep.assert_not_called()

    def test_post_has_bounded_retries_and_honors_retry_after(self):
        client = HttpClient(timeout=20, attempts=2)
        client.session.post = Mock(side_effect=[
            self.response(429, **{"Retry-After": "7"}), self.response(200),
        ])
        with patch("phishing_army.http.time.sleep") as sleep:
            response = client.post("https://example.com/purge", json={"files": []})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(client.session.post.call_count, 2)
        self.assertEqual(client.session.post.call_args.kwargs["timeout"], 20)
        sleep.assert_called_once_with(7.0)
