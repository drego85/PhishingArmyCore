#!/usr/bin/env python3
"""Backward-compatible entry point for the Phishing Army generator."""

from phishing_army.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
