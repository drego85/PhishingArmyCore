import gzip
import unittest

from phishing_army.config import Settings
from phishing_army.sources import (
    Source,
    fetch_antiphish,
    fetch_certpl,
    fetch_phishtank,
    fetch_urlabuse,
    fetch_urlscan,
    fetch_phishstats,
    fetch_stalkphish,
)


class Response:
    def __init__(self, payload, text="", content=b""):
        self._payload = payload
        self.text = text
        self.content = content

    def json(self):
        return self._payload


class Client:
    def __init__(self, payload, text="", content=b""):
        self.payload = payload
        self.text = text
        self.content = content
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return Response(self.payload, self.text, self.content)


class SourceTests(unittest.TestCase):
    def test_api_error_or_changed_schema_is_failed_but_empty_feed_is_valid(self):
        for fetcher, empty in (
            (fetch_antiphish, {"data": []}),
            (fetch_urlscan, {"results": []}),
            (fetch_phishstats, []),
            (fetch_stalkphish, []),
        ):
            with self.subTest(source=fetcher.__name__):
                source = Source("fixture", fetcher)
                for payload in ({"error": "maintenance"}, {"message": "unexpected"}):
                    self.assertEqual(source.fetch(Client(payload), Settings()).status, "failed")
                result = source.fetch(Client(empty), Settings())
                self.assertEqual(result.status, "ok")
                self.assertEqual(result.indicators, set())

    def test_phishtank_rejects_html_instead_of_csv(self):
        result = Source("PhishTank", fetch_phishtank).fetch(
            Client({}, content=b"<html>Access denied</html>"), Settings()
        )
        self.assertEqual(result.status, "failed")

    def test_antiphish_filters_threat_type(self):
        client = Client(
            {"data": [
                {"threat_type": "phishing", "host": "bad.example"},
                {"threat_type": "malware", "host": "skip.example"},
            ]}
        )
        self.assertEqual(list(fetch_antiphish(client, Settings())), ["bad.example"])

    def test_certpl_uses_v2_active_domain_feed(self):
        client = Client({}, text="first.example\nsecond.example\n")
        self.assertEqual(
            list(fetch_certpl(client, Settings())),
            ["first.example", "second.example"],
        )
        self.assertEqual(
            client.calls[0][0], "https://hole.cert.pl/domains/v2/domains.txt"
        )

    def test_phishtank_uses_csv_gzip_and_filters_inactive_rows(self):
        csv_payload = (
            "phish_id,url,phish_detail_url,submission_time,verified,"
            "verification_time,online,target\n"
            "1,https://active.example/path,,2026-01-01,yes,2026-01-01,yes,Example\n"
            "2,https://offline.example/path,,2026-01-01,yes,2026-01-01,no,Example\n"
            "3,https://unverified.example/path,,2026-01-01,no,,yes,Example\n"
        ).encode()
        client = Client({}, content=gzip.compress(csv_payload))
        values = list(fetch_phishtank(client, Settings(phishtank_token="secret")))
        self.assertEqual(values, ["https://active.example/path"])
        self.assertTrue(client.calls[0][0].endswith("/online-valid.csv.gz"))
        self.assertEqual(
            client.calls[0][1]["headers"]["User-Agent"],
            "phishtank/phishingarmy",
        )

    def test_urlscan_uses_agreed_query_and_task_url(self):
        client = Client({"results": [{"task": {"url": "https://bad.example/a"}}]})
        values = list(fetch_urlscan(client, Settings(urlscan_token="secret")))
        self.assertEqual(values, ["https://bad.example/a"])
        params = client.calls[0][1]["params"]
        self.assertIn('task.tags:("phishing" OR "malicious")', params["q"])
        self.assertNotIn("date:", params["q"])
        self.assertNotIn("sinking-yachts", params["q"])

    def test_urlabuse_uses_latest_window_and_filters_phishing(self):
        client = Client(
            {
                "success": True,
                "code": 200,
                "attr": [
                    {"rowid": 3, "rtype": "phishing", "url": "https://bad.example/a"},
                    {"rowid": 2, "rtype": "bet", "url": "https://skip.example/"},
                    {"rowid": 1, "rtype": "PHISHING", "url": "https://other.example/"},
                ],
            }
        )
        settings = Settings(
            urlabuse_email="account@example.com",
            urlabuse_token="secret",
        )
        self.assertEqual(
            list(fetch_urlabuse(client, settings)),
            ["https://bad.example/a", "https://other.example/"],
        )
        self.assertEqual(
            client.calls[0][0], "https://urlabuse.com/get_record_by_rowid"
        )
        params = client.calls[0][1]["params"]
        self.assertEqual(params["email"], "account@example.com")
        self.assertEqual(params["token"], "secret")
        self.assertNotIn("rowid", params)
        self.assertNotIn("acl", params)
        self.assertEqual(client.calls[0][1]["attempts"], 1)

    def test_urlabuse_rejects_unsuccessful_response(self):
        client = Client({"success": False, "code": 400, "msg": "not active"})
        with self.assertRaisesRegex(RuntimeError, "not active"):
            list(
                fetch_urlabuse(
                    client,
                    Settings(
                        urlabuse_email="account@example.com",
                        urlabuse_token="secret",
                    ),
                )
            )

    def test_source_errors_redact_all_tokens(self):
        def fail(client, settings):
            raise RuntimeError(
                "request contains "
                f"{settings.phishtank_token} "
                f"{settings.urlabuse_token} "
                "private%40example.com"
            )

        result = Source("fixture", fail).fetch(
            Client({}),
            Settings(
                phishtank_token="do-not-log-this",
                urlabuse_email="private@example.com",
                urlabuse_token="urlabuse-secret",
            ),
        )
        self.assertEqual(result.status, "failed")
        self.assertNotIn("do-not-log-this", result.error)
        self.assertNotIn("urlabuse-secret", result.error)
        self.assertNotIn("private@example.com", result.error)
        self.assertNotIn("private%40example.com", result.error)
        self.assertIn("[redacted]", result.error)

    def test_urlabuse_skips_when_credentials_are_incomplete(self):
        source = Source(
            "URLAbuse",
            fetch_urlabuse,
            ("urlabuse_email", "urlabuse_token"),
        )
        result = source.fetch(Client({}), Settings(urlabuse_token="secret"))
        self.assertEqual(result.status, "skipped")
        self.assertIn("urlabuse_email", result.error)


if __name__ == "__main__":
    unittest.main()
