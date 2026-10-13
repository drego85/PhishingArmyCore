import json
import stat
import tempfile
import unittest
from pathlib import Path

from phishing_army.builder import TEST_DOMAINS, BuildResult, build
from phishing_army.config import Settings
from phishing_army.domain import WhitelistPolicy
from phishing_army.output import LEGACY_FILES, generation_lock, publish, validate_publish
from phishing_army.sources import Source
from phishing_army.sources import SourceResult


class OutputTests(unittest.TestCase):
    def test_generation_lock_rejects_overlapping_builds_and_releases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with generation_lock(root):
                with self.assertRaisesRegex(RuntimeError, "already running"):
                    with generation_lock(root):
                        self.fail("second build acquired a held lock")
            with generation_lock(root):
                pass

    def test_legacy_files_are_identical(self):
        result = BuildResult(
            {"z.example", "a.example"},
            [SourceResult("fixture", {"z.example", "a.example"})],
            2,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = publish(result, root, minimum_entries=1)
            self.assertEqual(
                (root / LEGACY_FILES[0]).read_bytes(),
                (root / LEGACY_FILES[1]).read_bytes(),
            )
            content = (root / "phishing-army-domains.txt").read_text()
            self.assertIn(
                "Aggregated from independent phishing intelligence sources.", content
            )
            self.assertIn("Data sources, acknowledgements", content)
            self.assertIn("URLAbuse", content)
            self.assertLess(content.index("a.example\n"), content.index("z.example\n"))
            stored = json.loads((root / "phishing-army-manifest.json").read_text())
            self.assertEqual(stored["entries"], 2)
            self.assertEqual(manifest["entries"], 2)
            unbound = (root / "phishing-army-unbound.conf").read_text()
            self.assertIn('server:\n    local-zone: "a.example." always_nxdomain', unbound)
            dnsmasq = (root / "phishing-army-dnsmasq.conf").read_text()
            self.assertIn("local=/a.example/", dnsmasq)
            mode = stat.S_IMODE((root / LEGACY_FILES[0]).stat().st_mode)
            self.assertEqual(mode, 0o644)

    def test_refuses_empty_source_set(self):
        result = BuildResult(set(), [SourceResult("bad", status="failed")], 0)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(RuntimeError):
                publish(result, Path(directory), minimum_entries=0)

    def test_harmless_test_is_in_every_format_and_both_legacy_files(self):
        result = build(
            Settings(), WhitelistPolicy(set(), set(), set(), set()),
            sources=[Source("fixture", lambda c, s: ["phish-example.com"])],
        )
        expected = {
            "phishing-army-domains.txt": lambda d: f"{d}\n",
            "phishing-army-adblock.txt": lambda d: f"||{d}^\n",
            "phishing-army-hosts.txt": lambda d: f"0.0.0.0 {d}\n",
            "phishing-army-dnsmasq.conf": lambda d: f"local=/{d}/\n",
            "phishing-army-wildcard.txt": lambda d: f"*.{d}\n",
            "phishing-army-unbound.conf": lambda d: f'local-zone: "{d}." always_nxdomain\n',
            "phishing-army-rpz.zone": lambda d: f"{d} CNAME .\n*.{d} CNAME .\n",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = publish(result, root, minimum_entries=1)
            self.assertEqual(manifest["test_domains"], sorted(TEST_DOMAINS))
            self.assertEqual(manifest["raw_indicators"], 1)
            self.assertEqual(manifest["entries"], 3)
            self.assertEqual(len(manifest["sources"]), 1)
            for name, render_entry in expected.items():
                with self.subTest(format=name):
                    content = (root / name).read_text()
                    for domain in sorted(TEST_DOMAINS):
                        self.assertIn(render_entry(domain), content)
                    self.assertIn(
                        "Harmless filtering test: amiprotected.it, www.amiprotected.it",
                        content,
                    )
                    self.assertIn("they are not phishing reports", content)
            canonical = (root / "phishing-army-domains.txt").read_bytes()
            for name in LEGACY_FILES:
                self.assertEqual((root / name).read_bytes(), canonical)

    def test_test_domain_does_not_count_as_a_healthy_source(self):
        result = build(
            Settings(), WhitelistPolicy(set(), set(), set(), set()), sources=[],
        )
        self.assertEqual(result.domains, set(TEST_DOMAINS))
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, "no source completed successfully"):
                publish(result, Path(directory), minimum_entries=0)

    def test_test_domain_cannot_satisfy_minimum_source_entries(self):
        result = BuildResult(
            set(TEST_DOMAINS), [SourceResult("fixture", set())], 0,
            set(TEST_DOMAINS),
        )
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, "only 0 source-derived entries"):
                publish(result, Path(directory), minimum_entries=1)

    def test_size_ratio_excludes_test_from_both_snapshots(self):
        result = BuildResult(
            {f"phish{i}.example" for i in range(24)} | set(TEST_DOMAINS),
            [SourceResult("fixture", {f"phish{i}.example" for i in range(24)})],
            24,
            set(TEST_DOMAINS),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / LEGACY_FILES[1]).write_text(
                "".join(f"{domain}\n" for domain in sorted(TEST_DOMAINS))
                + "".join(f"phish{i}.example\n" for i in range(100))
            )
            with self.assertRaisesRegex(RuntimeError, "previous source-derived list"):
                validate_publish(result, root, minimum_entries=1)
            result.domains.add("phish24.example")
            validate_publish(result, root, minimum_entries=1)


if __name__ == "__main__":
    unittest.main()
