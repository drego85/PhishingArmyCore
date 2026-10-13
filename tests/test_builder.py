import unittest

from phishing_army.builder import TEST_DOMAINS, build, live_lookup
from phishing_army.config import Settings
from phishing_army.domain import WhitelistPolicy
from phishing_army.sources import Source


class BuilderTests(unittest.TestCase):
    def test_malformed_indicator_does_not_cancel_healthy_sources(self):
        result = build(
            Settings(), WhitelistPolicy(set(), set(), set(), set()),
            sources=[
                Source("good", lambda c, s: ["https://phish-example.com/login"]),
                Source("mixed", lambda c, s: ["https://[broken/", "other-phish.net"]),
            ],
        )
        self.assertEqual(result.domains, {"phish-example.com", "other-phish.net"} | TEST_DOMAINS)
        self.assertEqual(result.successful_sources, 2)

    def test_harmless_domain_is_added_without_upstream_attribution(self):
        result = build(
            Settings(), WhitelistPolicy(set(), set(), set(), set()),
            sources=[Source("fixture", lambda c, s: ["phish-example.com"])],
        )
        self.assertEqual(result.test_domains, set(TEST_DOMAINS))
        self.assertEqual(result.domains, {"phish-example.com"} | TEST_DOMAINS)
        self.assertEqual(result.raw_indicators, 1)
        self.assertEqual(result.successful_sources, 1)
        self.assertEqual(live_lookup("amiprotected.it", result), [])

    def test_harmless_domain_is_not_disabled_by_popularity_whitelist(self):
        result = build(
            Settings(), WhitelistPolicy({"amiprotected.it"}, set(), set(), set()),
            sources=[],
        )
        self.assertEqual(result.domains, set(TEST_DOMAINS))
        self.assertEqual(result.successful_sources, 0)

    def test_personal_whitelist_still_overrides_harmless_domains(self):
        cases = {
            "amiprotected.it": set(),
            "www.amiprotected.it": set(),
            "allowed.amiprotected.it": {"www.amiprotected.it"},
        }
        for allowed, expected in cases.items():
            with self.subTest(allowed=allowed):
                result = build(
                    Settings(), WhitelistPolicy(set(), {allowed}, set(), set()),
                    sources=[],
                )
                self.assertEqual(result.domains, expected)
                self.assertEqual(result.test_domains, expected)

    def test_real_indicators_are_not_carried_forward_with_test_domain(self):
        policy = WhitelistPolicy(set(), set(), set(), set())
        first = build(
            Settings(), policy,
            sources=[Source("fixture", lambda c, s: ["old-phish.com"])],
        )
        second = build(
            Settings(), policy,
            sources=[Source("fixture", lambda c, s: ["new-phish.com"])],
        )
        self.assertIn("old-phish.com", first.domains)
        self.assertNotIn("old-phish.com", second.domains)
        self.assertEqual(second.domains, {"new-phish.com"} | TEST_DOMAINS)
