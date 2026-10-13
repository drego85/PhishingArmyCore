from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from contextlib import nullcontext

from .builder import build, live_lookup
from .cache import purge_cloudflare
from .config import load_settings
from .domain import WhitelistPolicy, normalize_domain
from .maintenance import compare_with_public, generate_whitelist_candidate
from .output import generation_lock, publish


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate and investigate Phishing Army feeds")
    subparsers = parser.add_subparsers(dest="command")
    build_parser = subparsers.add_parser("build", help="fetch live sources and generate feeds")
    build_parser.add_argument("--output", type=Path)
    build_parser.add_argument("--dry-run", action="store_true")
    build_parser.add_argument("--minimum-entries", type=int, default=100)
    build_parser.add_argument("--minimum-previous-ratio", type=float, default=0.25)
    lookup_parser = subparsers.add_parser("lookup", help="search a domain in current live feeds")
    lookup_parser.add_argument("domain")
    compare_parser = subparsers.add_parser("compare", help="compare a candidate with the public list")
    compare_parser.add_argument("candidate", type=Path)
    whitelist_parser = subparsers.add_parser(
        "whitelist-candidate", help="create a manually reviewed Tranco whitelist candidate"
    )
    whitelist_parser.add_argument("--output", type=Path)
    subparsers.add_parser("purge-cache", help="retry a configured public-feed cache purge")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command is None:
        args = _parser().parse_args(["build"])
    command = args.command or "build"
    logging.basicConfig(
        filename="phishing.log",
        format="%(asctime)s %(levelname)s %(message)s",
        level=logging.INFO,
    )
    settings = load_settings()
    try:
        if command == "build":
            policy = WhitelistPolicy.from_directory(PROJECT_ROOT / "list")
            output = args.output if args.output is not None else settings.output_directory
            with nullcontext() if args.dry_run else generation_lock(output):
                result = build(settings, policy)
                manifest = publish(
                    result,
                    output,
                    dry_run=args.dry_run,
                    minimum_entries=args.minimum_entries,
                    minimum_previous_ratio=args.minimum_previous_ratio,
                )
                if not args.dry_run and args.output is None:
                    purge = purge_cloudflare(settings, manifest)
                    if purge["status"] == "failed":
                        logging.warning(
                            "Feeds published; Cloudflare cache purge failed: %s", purge["error"]
                        )
                    elif purge["status"] == "ok":
                        logging.info("Cloudflare cache purged for %d URLs", purge["urls"])
                    # Operational status stays outside the already installed public manifest.
                    manifest = {**manifest, "cloudflare_purge": purge}
            print(json.dumps(manifest, indent=2, sort_keys=True))
            return 0
        if command == "purge-cache":
            with generation_lock(settings.output_directory):
                manifest = json.loads(
                    (settings.output_directory / "phishing-army-manifest.json").read_text(
                        encoding="utf-8"
                    )
                )
                purge = purge_cloudflare(settings, manifest)
            print(json.dumps(purge, indent=2, sort_keys=True))
            return 0 if purge["status"] == "ok" else 2
        if command == "lookup":
            policy = WhitelistPolicy.from_directory(PROJECT_ROOT / "list")
            result = build(settings, policy)
            matches = live_lookup(args.domain, result)
            target = normalize_domain(args.domain)
            test_domains = sorted(
                domain for domain in result.test_domains
                if target and domain == target.fqdn
            )
            report = {
                "query": args.domain,
                "notice": "Live sources may differ from the last published build.",
                "matches": [
                    {"source": source, "domains": domains} for source, domains in matches
                ],
                "local_test_domains": test_domains,
                "sources": [
                    {"name": item.name, "status": item.status, "error": item.error}
                    for item in result.sources
                ],
            }
            print(json.dumps(report, indent=2, sort_keys=True))
            return 0 if matches or test_domains else 1
        if command == "compare":
            print(json.dumps(compare_with_public(args.candidate), indent=2, sort_keys=True))
            return 0
        if command == "whitelist-candidate":
            report = generate_whitelist_candidate(PROJECT_ROOT / "list", args.output)
            print(json.dumps(report, indent=2, sort_keys=True))
            return 0
    except Exception as error:
        logging.exception("Command %s failed", command)
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 2
