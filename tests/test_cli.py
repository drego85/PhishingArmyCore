import io
import json
import unittest
from unittest.mock import patch

from phishing_army.builder import BuildResult
from phishing_army.cli import main
from phishing_army.config import Settings
from phishing_army.domain import WhitelistPolicy
from phishing_army.sources import SourceResult


class LookupTests(unittest.TestCase):
    def test_local_test_is_identified_without_fake_provider_match(self):
        result = BuildResult(
            {"amiprotected.it", "www.amiprotected.it", "phish-example.com"},
            [SourceResult("fixture", {"phish-example.com"})],
            1,
            {"amiprotected.it", "www.amiprotected.it"},
        )
        for hostname in ("amiprotected.it", "www.amiprotected.it"):
            with self.subTest(hostname=hostname):
                output = io.StringIO()
                with patch("phishing_army.cli.load_settings", return_value=Settings()), \
                        patch("phishing_army.cli.logging.basicConfig"), \
                        patch("phishing_army.cli.WhitelistPolicy.from_directory",
                              return_value=WhitelistPolicy(set(), set(), set(), set())), \
                        patch("phishing_army.cli.build", return_value=result), \
                        patch("sys.stdout", output):
                    code = main(["lookup", f"https://{hostname}/"])
                report = json.loads(output.getvalue())
                self.assertEqual(code, 0)
                self.assertEqual(report["matches"], [])
                self.assertEqual(report["local_test_domains"], [hostname])
                self.assertEqual([source["name"] for source in report["sources"]], ["fixture"])
