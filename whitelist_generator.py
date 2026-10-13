#!/usr/bin/env python3
"""Generate a reviewable whitelist candidate; never replaces the approved list."""

from phishing_army.cli import main


if __name__ == "__main__":
    raise SystemExit(main(["whitelist-candidate"]))
