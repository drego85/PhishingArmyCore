import io
import tempfile
import unittest
import zipfile
from pathlib import Path

from phishing_army.maintenance import (
    _candidate_conflicts, generate_whitelist_candidate, parse_domain_list,
)


class Response:
    def __init__(self, *, text="", content=b""):
        self.text = text
        self.content = content


class Client:
    def __init__(self, archive, public=""):
        self.archive = archive
        self.public = public

    def get(self, url, **kwargs):
        if url.endswith("top-1m.csv.zip"):
            return Response(content=self.archive)
        if url.endswith("top-1m-id"):
            return Response(text="TEST-ID")
        if "phishing.army/download/" in url:
            return Response(text=self.public)
        return Response(text="allow-example.com\n")


class MaintenanceTests(unittest.TestCase):
    def test_candidate_conflicts_respect_nested_shared_boundaries(self):
        boundary = "hosted.example.com"
        tenant = f"synthetic-reported-tenant.{boundary}"
        self.assertEqual(
            _candidate_conflicts(
                {"example.com", boundary, tenant}, {tenant}, {boundary}
            ),
            {tenant},
        )
        self.assertEqual(
            _candidate_conflicts(
                {"example.com", boundary}, {tenant, "reported.example.com"}, {boundary}
            ),
            {"example.com"},
        )

    def test_candidate_conflicts_still_reject_a_ranked_private_psl_tenant(self):
        tenant = "synthetic-reported-tenant.vercel.app"
        self.assertEqual(
            _candidate_conflicts({"vercel.app", tenant}, {tenant}, set()),
            {tenant},
        )

    def test_candidate_cannot_target_active_policy_or_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "global_whitelist.txt"
            active.write_text("approved-example.com\n")
            alias = root / "alias.txt"
            alias.symlink_to(active)
            for target in (active, alias, root / "personal_whitelist.txt"):
                with self.subTest(target=target), self.assertRaises(ValueError):
                    generate_whitelist_candidate(root, target, Client(b""))
            self.assertEqual(active.read_text(), "approved-example.com\n")
            candidate = root / "candidate.txt"
            candidate.with_suffix(".txt.metadata.json").symlink_to(active)
            with self.assertRaises(ValueError):
                generate_whitelist_candidate(root, candidate, Client(b""))
            self.assertEqual(active.read_text(), "approved-example.com\n")

    def test_list_parser_understands_domains_hosts_and_adblock(self):
        parsed = parse_domain_list(
            "# banner\nexample.com\n0.0.0.0 host.example.net\n||ads.example.org^\n"
        )
        self.assertEqual(
            parsed, {"example.com", "host.example.net", "ads.example.org"}
        )

    def test_whitelist_candidate_never_replaces_approved_file(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("top-1m.csv", "1,tranco-example.com\n2,www.second-example.net\n")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            approved = root / "global_whitelist.txt"
            approved.write_text("approved-example.com\n", encoding="utf-8")
            (root / "business_domains.txt").write_text(
                "www.business-example.org\n", encoding="utf-8"
            )
            report = generate_whitelist_candidate(
                root, client=Client(buffer.getvalue())
            )
            self.assertEqual(approved.read_text(), "approved-example.com\n")
            candidate = root / "global_whitelist.candidate.txt"
            self.assertTrue(candidate.exists())
            self.assertEqual(report["tranco_id"], "TEST-ID")
            self.assertTrue(candidate.with_suffix(".txt.metadata.json").exists())

    def test_whitelist_candidate_excludes_current_blocklist_namespaces(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr(
                "top-1m.csv",
                "1,legitimate.example\n2,shared-example.com\n3,wixstudio.com\n",
            )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "global_whitelist.txt").write_text("", encoding="utf-8")
            (root / "shared_subdomain_services.txt").write_text(
                "", encoding="utf-8"
            )
            report = generate_whitelist_candidate(
                root,
                client=Client(
                    buffer.getvalue(),
                    public=(
                        "phishing.shared-example.com\n"
                        "phishing-campaign.wixstudio.com\n"
                    ),
                ),
            )
            candidate = parse_domain_list(
                (root / "global_whitelist.candidate.txt").read_text()
            )
            self.assertNotIn("shared-example.com", candidate)
            self.assertIn("wixstudio.com", candidate)
            self.assertEqual(report["excluded_current_blocklist_conflicts"], 1)


if __name__ == "__main__":
    unittest.main()
