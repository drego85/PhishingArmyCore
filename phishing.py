#!/usr/bin/env python3
# This file is part of Phishing Army.
#
# Phishing Army was made with ♥ by Andrea Draghetti
#
# This file may be licensed under the terms of of the
# GNU General Public License Version 3 (the ``GPL'').
#
import os
import sys
import gzip
import json
import Config
import logging
import requests
import tldextract
from datetime import datetime

timeout_connection = 120
header_desktop = {"User-Agent": "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)",
                  "Accept-Language": "it,en-US;q=0.7,en;q=0.3"}

header_phishtank = {"User-Agent": "phishtank/phishingarmy",
                    "Accept-Language": "it,en-US;q=0.7,en;q=0.3"}


block_list = set()
block_list_extended = set()
white_list = set()

# LOG initialization
logging.basicConfig(filename="phishing.log",
                    format="%(asctime)s - %(funcName)10s():%(lineno)s - %(levelname)s - %(message)s",
                    level=logging.INFO)


def parse_domain(url):
    url = url.lower()
    ext = tldextract.extract(url)
    registered_domain = ext.top_domain_under_public_suffix
    sub_domain = ext.subdomain

    # Remove punycode domain
    registered_domain = registered_domain.encode("idna").decode("utf-8")
    sub_domain = sub_domain.encode("idna").decode("utf-8")

    if sub_domain:
        full_domain = sub_domain + "." + registered_domain
    else:
        full_domain = registered_domain

    if registered_domain and registered_domain not in white_list:
        block_list.add(full_domain)
        block_list_extended.add(full_domain)

        if sub_domain == "www":
            block_list_extended.add(registered_domain)

        # This integration has been suspended to avoid false positives.
        #
        # if full_domain != registered_domain:
        #    block_list_extended.add(registered_domain)


# Download data from phishtank.com
def phishtank():
    url_download = "https://data.phishtank.com/data/" + Config.phishtanktoken + "/online-valid.json.gz"

    try:
        r = requests.get(url_download, headers=header_phishtank, timeout=timeout_connection)

        if r.status_code == 200:

            with open("./list/online-valid.json.gz", "wb") as f:
                f.write(r.content)

            f = gzip.open("./list/online-valid.json.gz", "rb")
            file_content = f.read()
            f.close()

            data = json.loads(file_content)

            if data:
                for each in data:
                    url = each["url"]
                    if url:
                        url = url.strip()
                        parse_domain(url)

    except Exception as e:
        logging.error(e, exc_info=True)
        raise


# Download data from Urlscan.io
def urlscanio():
    url_download = ["https://urlscan.io/api/v1/search/?q=task.tags:%22sinking-yachts%22",
                    "https://urlscan.io/api/v1/search/?q=task.tags:%22%23phishing%22"]

    for url in url_download:
        try:
            r = requests.get(url, headers=header_desktop, timeout=timeout_connection)

            if r.status_code == 200:

                data = json.loads(r.text)

                if data:
                    for each in data["results"]:
                        url = each["task"]["url"].lower()
                        if url:
                            url = url.strip()
                            parse_domain(url)

        except Exception as e:
            logging.error(e, exc_info=True)
            raise


# Download data from OpenPhish
def openphish():
    url_download = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"

    try:
        r = requests.get(url_download, headers=header_desktop, timeout=timeout_connection)

        if r.status_code == 200:
            for line in r.iter_lines(decode_unicode=True):
                if line:
                    url = line.strip()
                    parse_domain(url)

    except Exception as e:
        logging.error(e, exc_info=True)
        raise


# Download data from PhishFindR
def phishfindr():
    url_list = [
        "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE-NOW.txt",
        "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE-TODAY.txt",
        "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-NEW-last-hour.txt",
        "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-NEW-today.txt",
        "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt"]

    for url_download in url_list:
        try:
            r = requests.get(url_download, headers=header_desktop, timeout=timeout_connection)

            if r.status_code == 200:
                for line in r.iter_lines(decode_unicode=True):
                    if line:
                        url = line.strip()
                        parse_domain(url)

        except Exception as e:
            logging.error(e, exc_info=True)
            raise


# Download data from Cert.pl
def certpl():
    url_download = "https://hole.cert.pl/domains/domains.txt"

    try:
        r = requests.get(url_download, headers=header_desktop, timeout=timeout_connection)

        if r.status_code == 200:
            for line in r.iter_lines(decode_unicode=True):
                if line:
                    url = line.strip()
                    parse_domain(url)

    except Exception as e:
        logging.error(e, exc_info=True)
        raise


# Download data from Phishunt.io
def phishuntio():
    url_download = "https://phishunt.io/feed.txt"

    try:
        r = requests.get(url_download, headers=header_desktop, timeout=timeout_connection)

        if r.status_code == 200:
            for line in r.iter_lines(decode_unicode=True):
                if line:
                    url = line.strip()
                    parse_domain(url)

    except Exception as e:
        logging.error(e, exc_info=True)
        raise


# Load WhiteList
def whitelist():
    try:
        f = open("./list/global_whitelist.txt", "r")

        for line in f:
            if line:
                line = line.strip()
                line = line.lower()
                if not line.startswith("#"):
                    white_list.add(line)
        f.close()

    except Exception as e:
        logging.error(e, exc_info=True)
        pass

    # Load Personal Whitelist
    try:
        f = open("./list/personal_whitelist.txt", "r")

        for line in f:
            if line:
                line = line.strip()
                line = line.lower()
                if not line.startswith("#"):
                    white_list.add(line)
        f.close()

    except Exception as e:
        logging.error(e, exc_info=True)
        pass


def main():
    # Whitelist loading
    whitelist()
    logging.info("Loading %s domain in white_list" % len(white_list))

    # PhishTank loading
    phishtank()

    # OpenPhish loading
    openphish()

    # PhishFindR loading
    # phishfindr()

    # Cert.pl loading
    certpl()

    # Phishunt.io loading
    phishuntio()

    # Urlscan.io loading
    urlscanio()

    # Sort the generated lists
    block_list_sorted = sorted(block_list)
    block_list_extended_sorted = sorted(block_list_extended)

    logging.info("Generated the Blocklist containing %s domains" % len(block_list_sorted))
    logging.info("Generated the Extended Blocklist containing %s domains" % len(block_list_extended_sorted))

    banner = "# \n" \
             "# Phishing Army | The Blocklist to filter Phishing \n" \
             "# \n" \
             "# Last Update: %s\n" \
             "# \n" \
             "# Project website: https://phishing.army \n" \
             "# Support the project with a donation:: https://www.buymeacoffee.com/andreadraghetti \n" \
             "# \n" \
             "# This work is licensed under a Creative Commons Attribution-NonCommercial 4.0 International License. \n" \
             "# ======================================================================================================\n" % datetime.utcnow().strftime(
        "%a, %d %b %Y %H:%M:%S UTC")

    banner_extended = "# \n" \
                      "# Phishing Army | The Blocklist to filter Phishing \n" \
                      "# \n" \
                      "# Last Update: %s\n" \
                      "# \n" \
                      "# This is the extended version, also contains domains without subdomains.\n" \
                      "# \n" \
                      "# Project website: https://phishing.army \n" \
                      "# Support the project with a donation:: https://www.buymeacoffee.com/andreadraghetti \n" \
                      "# \n" \
                      "# This work is licensed under a Creative Commons Attribution-NonCommercial 4.0 International License. \n" \
                      "# ======================================================================================================\n" % datetime.utcnow().strftime(
        "%a, %d %b %Y %H:%M:%S UTC")

    # Write the blocklist files
    with open(Config.outputdirectory + "phishing_army_blocklist.txt", "w") as f:

        f.write("%s\n" % banner)

        for item in block_list_sorted:
            f.write("%s\n" % item)

    with open(Config.outputdirectory + "phishing_army_blocklist_extended.txt", "w") as f:

        f.write("%s\n" % banner_extended)

        for item in block_list_extended_sorted:
            f.write("%s\n" % item)


if __name__ == "__main__":
    main()
