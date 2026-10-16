import unittest
import tempfile
from pathlib import Path

from phishing_army.domain import (
    WhitelistPolicy, balanced_domains, load_domain_file, normalize_domain,
)


class DomainTests(unittest.TestCase):
    def test_normalizes_url_and_idna(self):
        parts = normalize_domain("HTTPS://Bücher.de/path?q=1")
        self.assertIsNotNone(parts)
        self.assertEqual(parts.fqdn, "xn--bcher-kva.de")

    def test_rejects_ip_and_invalid_value(self):
        self.assertIsNone(normalize_domain("https://192.0.2.1/path"))
        self.assertIsNone(normalize_domain("not a domain"))

    def test_malformed_urls_do_not_abort_other_indicators(self):
        policy = WhitelistPolicy(set(), set(), set(), set())
        malformed = {"https://[bad.example/", "https://example.com\uff0fevil.com/"}
        for value in malformed:
            self.assertIsNone(normalize_domain(value))
        self.assertEqual(
            balanced_domains(malformed | {"https://bad-example.com/path"}, policy),
            {"bad-example.com"},
        )

    def test_missing_required_policy_file_is_rejected(self):
        names = (
            "global_whitelist.txt", "personal_whitelist.txt",
            "shared_subdomain_services.txt", "path_shared_services.txt",
        )
        for missing in names:
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for name in names:
                    if name != missing:
                        (root / name).write_text("")
                with self.assertRaisesRegex(FileNotFoundError, missing):
                    WhitelistPolicy.from_directory(root)

    def test_allowed_descendant_prevents_a_broad_parent_block(self):
        for kind in ("personal", "global", "path_shared"):
            with self.subTest(kind=kind):
                policy = WhitelistPolicy(
                    {"safe.example.com"} if kind == "global" else set(),
                    {"safe.example.com"} if kind == "personal" else set(),
                    set(),
                    {"safe.example.com"} if kind == "path_shared" else set(),
                )
                self.assertEqual(
                    balanced_domains({"example.com", "safe.example.com", "evil.example.com"}, policy),
                    {"evil.example.com"},
                )

    def test_ranked_tenant_protects_only_its_own_namespace(self):
        policy = WhitelistPolicy({"netlify.app", "good.netlify.app"}, set(), {"netlify.app"}, set())
        self.assertEqual(
            balanced_domains({"netlify.app", "good.netlify.app", "sub.good.netlify.app", "bad.netlify.app"}, policy),
            {"bad.netlify.app"},
        )

    def test_private_suffix_root_can_be_whitelisted(self):
        root = normalize_domain("vercel.app")
        tenant = normalize_domain("phish.vercel.app")
        self.assertEqual(root.registered, "vercel.app")
        self.assertEqual(tenant.registered, "phish.vercel.app")

    def test_blob_url_uses_its_https_origin(self):
        parts = normalize_domain(
            "blob:https://starlit-salamander-174d60.netlify.app/"
            "0e7397cb-7122-4307-9e5c-c56d67865e0c"
        )
        self.assertEqual(
            parts.fqdn, "starlit-salamander-174d60.netlify.app"
        )

    def test_trusted_namespace_suppresses_descendants(self):
        policy = WhitelistPolicy({"example.com"}, set(), set(), set())
        self.assertEqual(balanced_domains({"login.example.com"}, policy), set())

    def test_shared_subdomain_service_allows_tenant_only(self):
        policy = WhitelistPolicy({"no-ip.com"}, set(), {"no-ip.com"}, set())
        self.assertEqual(
            balanced_domains({"phishing.no-ip.com", "no-ip.com"}, policy),
            {"phishing.no-ip.com"},
        )

    def test_private_psl_platform_overrides_tranco_namespace(self):
        policy = WhitelistPolicy({"wixstudio.com"}, set(), set(), set())
        self.assertEqual(
            balanced_domains(
                {"wixstudio.com", "phishing-campaign.wixstudio.com"}, policy
            ),
            {"phishing-campaign.wixstudio.com"},
        )

    def test_path_shared_service_is_suppressed(self):
        policy = WhitelistPolicy(set(), set(), set(), {"bit.ly"})
        self.assertEqual(balanced_domains({"bit.ly/bad", "www.bit.ly"}, policy), set())

    def test_link_me_profiles_do_not_block_the_shared_service(self):
        policy = WhitelistPolicy.from_directory(
            Path(__file__).resolve().parent.parent / "list"
        )
        self.assertIn("link.me", policy.path_shared_services)
        self.assertIn("link.me", policy.personal_domains)
        self.assertEqual(
            balanced_domains(
                {"https://link.me/suspicious-profile", "www.link.me", "link.me"},
                policy,
            ),
            set(),
        )

    def test_hoxhunt_training_domains_are_personally_whitelisted(self):
        catalog = WhitelistPolicy.from_directory(
            Path(__file__).resolve().parent.parent / "list"
        )
        policy = WhitelistPolicy(set(), catalog.personal_domains, set(), set())
        self.assertEqual(
            balanced_domains(
                {
                    "https://authentication.ms/training",
                    "https://security.email-microsoft.com/training",
                    "other.email-microsoft.com",
                    "authentication.ms.example.com",
                },
                policy,
            ),
            {"other.email-microsoft.com", "authentication.ms.example.com"},
        )

    def test_ftc_amazon_refund_site_is_personally_whitelisted(self):
        catalog = WhitelistPolicy.from_directory(
            Path(__file__).resolve().parent.parent / "list"
        )
        policy = WhitelistPolicy(set(), catalog.personal_domains, set(), set())
        self.assertEqual(
            balanced_domains(
                {
                    "subscriptionmembershipsettlement.com",
                    "https://www.subscriptionmembershipsettlement.com/",
                    "subscriptionmembershipsettlement.com.example.com",
                },
                policy,
            ),
            {"subscriptionmembershipsettlement.com.example.com"},
        )

    def test_google_search_ads_serving_domains_are_personally_whitelisted(self):
        policy = WhitelistPolicy.from_directory(
            Path(__file__).resolve().parent.parent / "list"
        )
        self.assertEqual(
            balanced_domains(
                {
                    "adsensecustomsearchads.com",
                    "www.adsensecustomsearchads.com",
                    "syndicatedsearch.goog",
                },
                policy,
            ),
            set(),
        )

    def test_personal_whitelist_has_precedence(self):
        policy = WhitelistPolicy(set(), {"netlify.app"}, {"netlify.app"}, set())
        self.assertEqual(balanced_domains({"phish.netlify.app"}, policy), set())

    def test_google_storage_boundary_protects_root_without_allowing_all_buckets(self):
        root = Path(__file__).resolve().parent.parent / "list"
        shared = load_domain_file(root / "shared_subdomain_services.txt", required=True)
        self.assertIn("storage.googleapis.com", shared)
        values = {
            "storage.googleapis.com",
            "https://storage.googleapis.com/synthetic-reported-bucket/login.html",
            "https://synthetic-reported-bucket.storage.googleapis.com/login.html",
            "sub.synthetic-reported-bucket.storage.googleapis.com",
        }
        expected = {
            "synthetic-reported-bucket.storage.googleapis.com",
            "sub.synthetic-reported-bucket.storage.googleapis.com",
        }
        for ranked in (set(), {"googleapis.com", "storage.googleapis.com"}):
            with self.subTest(ranked=ranked):
                # No personal exception: the catalog alone must protect the root.
                policy = WhitelistPolicy(ranked, set(), shared, set())
                self.assertEqual(balanced_domains(values, policy), expected)

    def test_discord_storage_personal_exception_does_not_allow_sibling_buckets(self):
        root = Path(__file__).resolve().parent.parent / "list"
        personal = load_domain_file(root / "personal_whitelist.txt", required=True)
        shared = load_domain_file(root / "shared_subdomain_services.txt", required=True)
        discord = "discord-attachments-uploads-prd.storage.googleapis.com"
        self.assertIn(discord, personal)
        self.assertNotIn("storage.googleapis.com", personal)
        policy = WhitelistPolicy({"googleapis.com"}, personal, shared, set())
        self.assertEqual(
            balanced_domains(
                {
                    "storage.googleapis.com",
                    f"https://{discord}/synthetic-file",
                    f"sub.{discord}",
                    "synthetic-reported-bucket.storage.googleapis.com",
                    f"{discord}.example.com",
                },
                policy,
            ),
            {"synthetic-reported-bucket.storage.googleapis.com", f"{discord}.example.com"},
        )

    def test_firebase_storage_path_service_is_protected_without_allowing_other_apis(self):
        root = Path(__file__).resolve().parent.parent / "list"
        firebase = "firebasestorage.googleapis.com"
        personal = load_domain_file(root / "personal_whitelist.txt", required=True)
        path_shared = load_domain_file(root / "path_shared_services.txt", required=True)
        shared = load_domain_file(root / "shared_subdomain_services.txt", required=True)
        self.assertIn(firebase, personal)
        self.assertIn(firebase, path_shared)
        self.assertNotIn("googleapis.com", personal)
        self.assertNotIn("googleapis.com", path_shared)
        values = {
            firebase,
            f"https://{firebase}/v0/b/synthetic-bucket/o/synthetic-file?alt=media",
            f"sub.{firebase}",
            "synthetic-reported-api.googleapis.com",
            "synthetic-reported-bucket.storage.googleapis.com",
            f"{firebase}.example.com",
        }
        for kind in ("personal", "path_shared"):
            with self.subTest(kind=kind):
                policy = WhitelistPolicy(
                    set(), personal if kind == "personal" else set(),
                    shared, path_shared if kind == "path_shared" else set(),
                )
                self.assertEqual(
                    balanced_domains(values, policy),
                    {
                        "synthetic-reported-api.googleapis.com",
                        "synthetic-reported-bucket.storage.googleapis.com",
                        f"{firebase}.example.com",
                    },
                )

    def test_duckdns_official_site_and_api_are_allowed_without_exempting_tenants(self):
        root = Path(__file__).resolve().parent.parent / "list"
        personal = load_domain_file(root / "personal_whitelist.txt", required=True)
        self.assertIn("www.duckdns.org", personal)
        self.assertNotIn("duckdns.org", personal)
        tenant = "synthetic-reported-tenant.duckdns.org"
        self.assertEqual(normalize_domain(tenant).private_suffix, "duckdns.org")
        values = {
            "duckdns.org",
            "www.duckdns.org",
            "https://www.duckdns.org/update?domains=synthetic-example",
            "sub.www.duckdns.org",
            tenant,
            f"www.{tenant}",
            "www.duckdns.org.example.com",
        }
        for ranked in (set(), {"duckdns.org"}):
            with self.subTest(ranked=ranked):
                policy = WhitelistPolicy(ranked, personal, set(), set())
                self.assertEqual(
                    balanced_domains(values, policy),
                    {tenant, f"www.{tenant}", "www.duckdns.org.example.com"},
                )

    def test_reviewed_shared_catalog_blocks_only_observed_tenants(self):
        catalog = WhitelistPolicy.from_directory(
            Path(__file__).resolve().parent.parent / "list"
        )
        boundaries = {
            "mybluehost.me": "mybluehost.me",
            "cloudwaysapps.com": "cloudwaysapps.com",
            "cloudclusters.net": "cloudclusters.net",
            "weebly.com": "weebly.com",
            "myclickfunnels.com": "myclickfunnels.com",
            "hosted.phplist.com": "phplist.com",
            "up.railway.app": "railway.app",
            "storage.googleapis.com": "googleapis.com",
        }
        for boundary, platform in boundaries.items():
            with self.subTest(boundary=boundary):
                self.assertIn(boundary, catalog.shared_subdomain_roots)
                tenant = f"synthetic-reported-tenant.{boundary}"
                sibling = f"synthetic-unreported-tenant.{boundary}"
                policy = WhitelistPolicy(
                    {platform, boundary}, set(), catalog.shared_subdomain_roots, set()
                )
                self.assertEqual(
                    balanced_domains({platform, boundary, f"https://{tenant}/login"}, policy),
                    {tenant},
                )
                self.assertNotIn(sibling, balanced_domains({tenant}, policy))
                self.assertEqual(balanced_domains({tenant}, policy), {tenant})

    def test_narrow_shared_boundaries_preserve_other_provider_namespaces(self):
        for platform, boundary in (
            ("phplist.com", "hosted.phplist.com"),
            ("railway.app", "up.railway.app"),
        ):
            with self.subTest(boundary=boundary):
                policy = WhitelistPolicy({platform}, set(), {boundary}, set())
                tenant = f"synthetic-reported-tenant.{boundary}"
                self.assertEqual(
                    balanced_domains({tenant, boundary, platform, f"docs.{platform}"}, policy),
                    {tenant},
                )

    def test_shared_catalog_keeps_personal_and_ranked_tenant_precedence(self):
        boundaries = (
            "mybluehost.me", "cloudwaysapps.com", "cloudclusters.net",
            "weebly.com", "myclickfunnels.com", "hosted.phplist.com", "up.railway.app",
            "storage.googleapis.com",
        )
        for boundary in boundaries:
            tenant = f"synthetic-reviewed-tenant.{boundary}"
            sibling = f"synthetic-reported-tenant.{boundary}"
            for kind in ("personal_root", "personal_tenant", "ranked_tenant"):
                with self.subTest(boundary=boundary, kind=kind):
                    personal = {boundary} if kind == "personal_root" else (
                        {tenant} if kind == "personal_tenant" else set()
                    )
                    ranked = {boundary, tenant} if kind == "ranked_tenant" else {boundary}
                    policy = WhitelistPolicy(ranked, personal, {boundary}, set())
                    self.assertEqual(
                        balanced_domains({tenant, f"sub.{tenant}", sibling, boundary}, policy),
                        set() if kind == "personal_root" else {sibling},
                    )

    def test_netlify_root_is_protected_but_malicious_tenant_is_blocked(self):
        policy = WhitelistPolicy(
            {"netlify.app"}, set(), {"netlify.app"}, set()
        )
        self.assertEqual(
            balanced_domains(
                {
                    "netlify.app",
                    "wonderful-cobbler-5c5f0e.netlify.app",
                    "https://fb-supportpage.netlify.app/live",
                },
                policy,
            ),
            {
                "wonderful-cobbler-5c5f0e.netlify.app",
                "fb-supportpage.netlify.app",
            },
        )

    def test_framer_media_root_is_protected_but_malicious_tenant_is_blocked(self):
        policy = WhitelistPolicy.from_directory(
            Path(__file__).resolve().parent.parent / "list"
        )
        self.assertEqual(
            balanced_domains(
                {
                    "framer.media",
                    "https://phishing-campaign.framer.media/login",
                },
                policy,
            ),
            {"phishing-campaign.framer.media"},
        )
    def test_vercel_root_is_protected_but_malicious_tenant_is_blocked(self):
        policy = WhitelistPolicy(
            {"vercel.app"}, set(), {"vercel.app"}, set()
        )
        self.assertEqual(
            balanced_domains(
                {
                    "vercel.app",
                    "https://groupservicesglsit.vercel.app/",
                    "https://confirm-address-changing.vercel.app/register?next=register",
                    "https://wetransdferpg.vercel.app/"
                    r"\x68\x74\x74\x70\x73\x3a\x2f\x2fnewarubapgew.vercel.app/",
                },
                policy,
            ),
            {
                "groupservicesglsit.vercel.app",
                "confirm-address-changing.vercel.app",
                "wetransdferpg.vercel.app",
            },
        )

    def test_only_www_is_promoted(self):
        policy = WhitelistPolicy(set(), set(), set(), set())
        self.assertEqual(
            balanced_domains({"www.evil.com", "login.other.net"}, policy),
            {"evil.com", "www.evil.com", "login.other.net"},
        )


if __name__ == "__main__":
    unittest.main()
