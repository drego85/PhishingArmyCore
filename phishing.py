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

header_phishtank = {"User-Agent": "Phishtank/phishingarmy",
                    "Accept-Language": "it,en-US;q=0.7,en;q=0.3"}

tldcache = tldextract.TLDExtract()

block_list = []
block_list_extended = []

# LOG initialization
logging.basicConfig(filename="phishing.log",
                    format="%(asctime)s - %(funcName)10s():%(lineno)s - %(levelname)s - %(message)s",
                    level=logging.INFO)


# Download data from phishtank.com
def phishtank():
    url_download = "https://data.phishtank.com/data/" + Config.phishtanktoken + "/online-valid.json.gz"

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
                url = each["url"].lower()
                if url:
                    url = url.rstrip()
                    registered_domain = tldcache(url).registered_domain
                    sub_domain = tldcache(url).subdomain
                    if sub_domain:
                        full_domain = sub_domain + "." + registered_domain
                    else:
                        full_domain = registered_domain

                    if registered_domain and registered_domain not in white_list:
                        block_list.append(full_domain)
                        block_list_extended.append(full_domain)
                        if full_domain != registered_domain:
                            block_list_extended.append(registered_domain)


# Download data from OpenPhishing.com
def openphish():
    url_download = "https://openphish.com/feed.txt"

    try:
        r = requests.get(url_download, headers=header_desktop, timeout=timeout_connection)

        if r.status_code == 200:
            for line in r.iter_lines(decode_unicode=True):
                if line:
                    line = line.rstrip()
                    url = line.lower()

                    registered_domain = tldcache(url).registered_domain
                    sub_domain = tldcache(url).subdomain

                    if sub_domain:
                        full_domain = sub_domain + "." + registered_domain
                    else:
                        full_domain = registered_domain

                    if registered_domain and registered_domain not in white_list:
                        block_list.append(full_domain)
                        block_list_extended.append(full_domain)
                        if full_domain != registered_domain:
                            block_list_extended.append(registered_domain)

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
                        line = line.rstrip()
                        url = line.lower()

                        registered_domain = tldcache(url).registered_domain
                        sub_domain = tldcache(url).subdomain

                        if sub_domain:
                            full_domain = sub_domain + "." + registered_domain
                        else:
                            full_domain = registered_domain

                        if registered_domain and registered_domain not in white_list:
                            block_list.append(full_domain)
                            block_list_extended.append(full_domain)
                            if full_domain != registered_domain:
                                block_list_extended.append(registered_domain)

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
                    line = line.rstrip()
                    url = line.lower()

                    registered_domain = tldcache(url).registered_domain
                    sub_domain = tldcache(url).subdomain

                    if sub_domain:
                        full_domain = sub_domain + "." + registered_domain
                    else:
                        full_domain = registered_domain

                    if registered_domain and registered_domain not in white_list:
                        block_list.append(full_domain)
                        block_list_extended.append(full_domain)
                        if full_domain != registered_domain:
                            block_list_extended.append(registered_domain)

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
                    line = line.rstrip()
                    url = line.lower()

                    registered_domain = tldcache(url).registered_domain
                    sub_domain = tldcache(url).subdomain

                    if sub_domain:
                        full_domain = sub_domain + "." + registered_domain
                    else:
                        full_domain = registered_domain

                    if registered_domain and registered_domain not in white_list:
                        block_list.append(full_domain)
                        block_list_extended.append(full_domain)
                        if full_domain != registered_domain:
                            block_list_extended.append(registered_domain)

    except Exception as e:
        logging.error(e, exc_info=True)
        raise


# Load WhiteList
def whitelist():
    # Set Global the Whitelist
    global white_list

    # List of whitelisted domain
    white_list = []

    try:
        url_download = "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt"
        r = requests.get(url_download, headers=header_desktop, timeout=timeout_connection)

        if r.status_code == 200:
            for line in r.iter_lines(decode_unicode=True):
                if line:
                    line = line.rstrip()
                    line = line.lower()
                    analyzed_domain = tldcache(line).registered_domain
                    if analyzed_domain:
                        white_list.append(analyzed_domain.lower())
    except Exception as e:
        logging.error(e, exc_info=True)
        pass

    try:
        url_download = "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/referral-sites.txt"
        r = requests.get(url_download, headers=header_desktop, timeout=timeout_connection)

        if r.status_code == 200:
            for line in r.iter_lines(decode_unicode=True):
                if line:
                    line = line.rstrip()
                    line = line.lower()
                    analyzed_domain = tldcache(line).registered_domain
                    if analyzed_domain:
                        white_list.append(analyzed_domain.lower())
    except Exception as e:
        logging.error(e, exc_info=True)
        pass

    try:
        url_download = "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/optional-list.txt"
        r = requests.get(url_download, headers=header_desktop, timeout=timeout_connection)

        if r.status_code == 200:
            for line in r.iter_lines(decode_unicode=True):
                if line:
                    line = line.rstrip()
                    line = line.lower()
                    analyzed_domain = tldcache(line).registered_domain
                    if analyzed_domain:
                        white_list.append(analyzed_domain.lower())
    except Exception as e:
        logging.error(e, exc_info=True)
        pass

    try:
        # Source https://s3.amazonaws.com/alexa-static/top-1m.csv.zip
        # gcut -d "," -f1 --complement top-1m.csv > alexa-top-1m.txt
        f = open("./list/alexa-top-1m.txt", "r")

        for line in f:
            if line:
                line = line.rstrip()
                line = line.lower()
                analyzed_domain = tldcache(line).registered_domain
                if analyzed_domain:
                    white_list.append(analyzed_domain)
        f.close()

    except Exception as e:
        logging.error(e, exc_info=True)
        pass

    try:
        f = open("./list/personal_whitelist.txt", "r")

        for line in f:
            if line:
                line = line.rstrip()
                line = line.lower()
                if not line.startswith("#"):
                    analyzed_domain = tldcache(line).registered_domain
                    if analyzed_domain:
                        white_list.append(analyzed_domain)
        f.close()

    except Exception as e:
        logging.error(e, exc_info=True)
        pass

    # Remove duplicate from list
    if white_list:
        white_list = list(set(white_list))


def main():
    # Whitelist loading
    whitelist()
    logging.info("Loading %s domain in white_list" % len(white_list))

    # PhishTank loading
    phishtank()

    # OpenPhish loading
    openphish()

    # PhishFindR loading
    phishfindr()

    # Cert.pl loading
    certpl()

    # Phishunt.io loading
    phishuntio()

    # Eliminate duplicates and sort the generated lists
    block_list_sorted = sorted(set(block_list))
    block_list_extended_sorted = sorted(set(block_list_extended))

    logging.info("Generated the Blocklist containing %s domains" % len(block_list_sorted))
    logging.info("Generated the Extended Blocklist containing %s domains" % len(block_list_extended_sorted))

    banner = "# \n" \
             "# Phishing Army | The Blocklist to filter Phishing \n" \
             "# \n" \
             "# Last Update: %s\n" \
             "# \n" \
             "# Project website: https://phishing.army \n" \
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
                      "# \n" \
                      "# This work is licensed under a Creative Commons Attribution-NonCommercial 4.0 International License. \n" \
                      "# ======================================================================================================\n" % datetime.utcnow().strftime(
        "%a, %d %b %Y %H:%M:%S UTC")

    # Procedo a scrivere il contenuto
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
