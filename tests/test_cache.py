import io
import json
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import Mock, patch

import requests

from phishing_army.cache import FEED_BASE_URL, purge_cloudflare
from phishing_army.cli import main
from phishing_army.config import Settings
from phishing_army.domain import WhitelistPolicy
from phishing_army.output import LEGACY_FILES, RENDERERS


class CacheTests(unittest.TestCase):
    def settings(self, **kwargs):
        return Settings(
            cloudflare_token="private-test-token",
            cloudflare_zone_id="a" * 32,
            **kwargs,
        )

    def manifest(self):
        return {"files": {name: {} for name in set(RENDERERS) | set(LEGACY_FILES)}}

    def client(self, payload=None, status=200):
        client = Mock()
        client.post.return_value.status_code = status
        client.post.return_value.json.return_value = payload or {"success": True}
        return client

    def test_purges_only_all_published_feed_urls(self):
        client = self.client()
        self.assertEqual(
            purge_cloudflare(self.settings(), self.manifest(), client),
            {"status": "ok", "urls": 10},
        )
        call = client.post.call_args
        self.assertEqual(
            call.args[0],
            "https://api.cloudflare.com/client/v4/zones/" + "a" * 32 + "/purge_cache",
        )
        self.assertFalse(call.kwargs["allow_redirects"])
        self.assertEqual(
            set(call.kwargs["json"]), {"files"}
        )
        self.assertEqual(
            set(call.kwargs["json"]["files"]),
            {FEED_BASE_URL + name for name in self.manifest()["files"]}
            | {FEED_BASE_URL + "phishing-army-manifest.json"},
        )

    def test_disabled_or_invalid_configuration_makes_no_request(self):
        for settings, status in (
            (Settings(), "disabled"),
            (Settings(cloudflare_token="test"), "failed"),
            (Settings(cloudflare_zone_id="a" * 32), "failed"),
            (Settings(cloudflare_token="test", cloudflare_zone_id="../wrong"), "failed"),
        ):
            with self.subTest(settings=settings):
                client = self.client()
                self.assertEqual(purge_cloudflare(settings, self.manifest(), client)["status"], status)
                client.post.assert_not_called()

    def test_rejects_manifest_that_could_purge_other_resources(self):
        for names in ({}, {"index.html": {}}, {"../private.txt": {}}):
            with self.subTest(names=names):
                client = self.client()
                self.assertEqual(
                    purge_cloudflare(self.settings(), {"files": names}, client)["status"],
                    "failed",
                )
                client.post.assert_not_called()

    def test_provider_errors_cannot_disclose_token(self):
        client = self.client({"success": False, "errors": ["private-test-token"]})
        reports = [purge_cloudflare(self.settings(), self.manifest(), client)]
        client.post.side_effect = requests.Timeout("private-test-token")
        reports.append(purge_cloudflare(self.settings(), self.manifest(), client))
        response = requests.Response()
        response.status_code = 403
        client.post.side_effect = requests.HTTPError("private-test-token", response=response)
        reports.append(purge_cloudflare(self.settings(), self.manifest(), client))
        for report in reports:
            self.assertEqual(report["status"], "failed")
            self.assertNotIn("private-test-token", json.dumps(report))
        self.assertNotIn("private-test-token", repr(self.settings()))

    def test_invalid_json_and_redirect_are_failures(self):
        client = self.client()
        client.post.return_value.json.side_effect = ValueError("private-test-token")
        self.assertEqual(purge_cloudflare(self.settings(), self.manifest(), client)["status"], "failed")
        client = self.client(status=302)
        self.assertEqual(purge_cloudflare(self.settings(), self.manifest(), client)["error"], "HTTP 302")

    def run_build(self, arguments, *, publish_error=None, purge_status="ok"):
        events = []
        stdout = io.StringIO()
        stderr = io.StringIO()

        def publish(*args, **kwargs):
            events.append("manifest_installed")
            if publish_error:
                raise publish_error
            return self.manifest()

        def purge(*args):
            events.append("purge")
            return (
                {"status": "ok", "urls": 10}
                if purge_status == "ok" else
                {"status": purge_status, "error": "HTTP 403"}
            )

        with patch("phishing_army.cli.load_settings", return_value=self.settings()), \
                patch("phishing_army.cli.logging.basicConfig"), \
                patch("phishing_army.cli.generation_lock", return_value=nullcontext()), \
                patch("phishing_army.cli.WhitelistPolicy.from_directory",
                      return_value=WhitelistPolicy(set(), set(), set(), set())), \
                patch("phishing_army.cli.build"), \
                patch("phishing_army.cli.publish", side_effect=publish), \
                patch("phishing_army.cli.purge_cloudflare", side_effect=purge), \
                patch("sys.stdout", stdout), patch("sys.stderr", stderr), \
                patch("phishing_army.cli.logging.exception"), \
                patch("phishing_army.cli.logging.warning"):
            code = main(arguments)
        return code, events, stdout.getvalue()

    def test_purge_runs_after_successful_production_publication(self):
        code, events, output = self.run_build(["build"])
        self.assertEqual(code, 0)
        self.assertEqual(events, ["manifest_installed", "purge"])
        self.assertEqual(json.loads(output)["cloudflare_purge"]["status"], "ok")

    def test_shadow_and_dry_run_never_purge(self):
        for args in (["build", "--output", "/tmp/shadow"], ["build", "--dry-run"]):
            with self.subTest(args=args):
                code, events, output = self.run_build(args)
                self.assertEqual(code, 0)
                self.assertNotIn("purge", events)
                self.assertNotIn("cloudflare_purge", json.loads(output))

    def test_unsafe_or_failed_publication_never_purges(self):
        code, events, _ = self.run_build(["build"], publish_error=RuntimeError("publication refused"))
        self.assertEqual(code, 2)
        self.assertNotIn("purge", events)

    def test_purge_failure_preserves_successful_publication_and_is_reported(self):
        code, events, output = self.run_build(["build"], purge_status="failed")
        self.assertEqual(code, 0)
        self.assertEqual(events, ["manifest_installed", "purge"])
        self.assertEqual(json.loads(output)["cloudflare_purge"]["status"], "failed")

    def test_manual_retry_does_not_fetch_or_publish_feeds(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "phishing-army-manifest.json").write_text(json.dumps(self.manifest()))
            with patch("phishing_army.cli.load_settings",
                       return_value=self.settings(output_directory=output)), \
                    patch("phishing_army.cli.logging.basicConfig"), \
                    patch("phishing_army.cli.build") as build, \
                    patch("phishing_army.cli.publish") as publish, \
                    patch("phishing_army.cli.purge_cloudflare",
                          return_value={"status": "ok", "urls": 10}), \
                    patch("sys.stdout", io.StringIO()):
                self.assertEqual(main(["purge-cache"]), 0)
            build.assert_not_called()
            publish.assert_not_called()
