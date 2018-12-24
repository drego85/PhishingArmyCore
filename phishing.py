#!/usr/bin/python3
import os
import sys
import gzip
import json
import logging
import requests
import tldextract
from datetime import datetime, timedelta

timeoutconnection = 120
headerdesktop = {"User-Agent": "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)",
                 "Accept-Language": "it"}
tldcache = tldextract.TLDExtract(cache_file="./.tld_set")

WhiteList = []
AlexaList = []
BlockList = []
BlockListExtended = []
BlockListWildcard = []

# Inizializzo i LOG ignorando i messaggi standard delle librerie requests e urllib3
logging.basicConfig(filename="phishing.log",
                    format="%(asctime)s - %(funcName)10s():%(lineno)s - %(levelname)s - %(message)s",
                    level=logging.INFO)


def phishtank():
    urldownload = "https://data.phishtank.com/data/online-valid.json.gz"

    r = requests.get(urldownload, headers=headerdesktop, timeout=timeoutconnection)

    if r.status_code is 200:

        with open("./list/online-valid.json.gz", "wb") as f:
            f.write(r.content)

        f = gzip.open("./list/online-valid.json.gz", "rb")
        file_content = f.read()
        f.close()

        data = json.loads(file_content)

        if data:
            for each in data:
                url = each["url"].lower()
                registered_domain = tldcache(url).registered_domain
                sub_domain = tldcache(url).subdomain
                if sub_domain:
                    full_domain = sub_domain + "." + registered_domain
                else:
                    full_domain = registered_domain

                if registered_domain and registered_domain not in WhiteList and registered_domain not in AlexaList:
                    BlockList.append(full_domain)
                    BlockListExtended.append(full_domain)
                    BlockListWildcard.append(registered_domain)
                    if full_domain != registered_domain:
                        BlockListExtended.append(registered_domain)


def openphish():
    urldownload = "https://openphish.com/feed.txt"

    try:
        r = requests.get(urldownload, headers=headerdesktop, timeout=timeoutconnection)

        if r.status_code is 200:
            for line in r.iter_lines():
                url = line.decode("utf-8")

                registered_domain = tldcache(url).registered_domain
                sub_domain = tldcache(url).subdomain

                if sub_domain:
                    full_domain = sub_domain + "." + registered_domain
                else:
                    full_domain = registered_domain

                if registered_domain and registered_domain not in WhiteList and registered_domain not in AlexaList:
                    BlockList.append(full_domain)
                    BlockListExtended.append(full_domain)
                    BlockListWildcard.append(registered_domain)
                    if full_domain != registered_domain:
                        BlockListExtended.append(registered_domain)

    except Exception as e:
        logging.error(e, exc_info=True)
        raise


def whitelist():
    urldownload = "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt"
    r = requests.get(urldownload, headers=headerdesktop, timeout=timeoutconnection)

    if r.status_code is 200:
        for line in r.iter_lines():
            line = line.decode("utf-8")
            if line:
                line = line.rstrip()
                line = line.lower()
                analyzeddomain = tldcache(line).registered_domain
                if analyzeddomain:
                    WhiteList.append(analyzeddomain.lower())

    urldownload = "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/referral-sites.txt"
    r = requests.get(urldownload, headers=headerdesktop, timeout=timeoutconnection)

    if r.status_code is 200:
        for line in r.iter_lines():
            line = line.decode("utf-8")
            if line:
                line = line.rstrip()
                line = line.lower()
                analyzeddomain = tldcache(line).registered_domain
                if analyzeddomain:
                    WhiteList.append(analyzeddomain.lower())

    urldownload = "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/optional-list.txt"
    r = requests.get(urldownload, headers=headerdesktop, timeout=timeoutconnection)

    if r.status_code is 200:
        for line in r.iter_lines():
            line = line.decode("utf-8")
            if line:
                line = line.rstrip()
                line = line.lower()
                analyzeddomain = tldcache(line).registered_domain
                if analyzeddomain:
                    WhiteList.append(analyzeddomain.lower())


def alexalist():
    # Source https://s3.amazonaws.com/alexa-static/top-1m.csv.zip
    f = open("./list/alexa-top-1m.txt", "r")

    for line in f:
        if line:
            line = line.rstrip()
            line = line.lower()
            analyzeddomain = tldcache(line).registered_domain
            if analyzeddomain:
                AlexaList.append(analyzeddomain)
    f.close()


def main():
    # Carico le Whitelist
    whitelist()
    logging.info("Download di %s dominii da WhiteList" % len(WhiteList))

    # Carico i TOP Domain provenienti da Alexa Rank
    alexalist()
    logging.info("Caricati %s dominii da Alexa" % len(AlexaList))

    # Carico le segnalazioni convalidate di Phishtank
    phishtank()

    # Carico le segnalazioni convalidate da OpenPhish
    # openphish()

    # Eliminio documenti e ordino le liste generate
    BlockList2 = sorted(set(BlockList))
    BlockListExtended2 = sorted(set(BlockListExtended))
    BlockListWildcard2 = sorted(set(BlockListWildcard))

    logging.info("Generata la Blocklist contenente %s dominii" % len(BlockList2))
    logging.info("Generata la Blocklist Extended contenente %s dominii" % len(BlockListExtended2))

    banner = "# \n" \
             "# Phishing Army | The Blocklist to filter Phishing \n" \
             "# \n" \
             "# Last Update: %s\n" \
             "# \n" \
             "# Project website: https://phishing.army \n" \
             "# ===================================================\n" % datetime.utcnow().strftime(
        "%a, %d %b %Y %H:%M:%S UTC")

    bannerextended = "# \n" \
                     "# Phishing Army | The Blocklist to filter Phishing \n" \
                     "# \n" \
                     "# Last Update: %s\n" \
                     "# \n" \
                     "# This is the extended version (also contains domains without subdomains), for the normal version go to the project website.\n" \
                     "# \n" \
                     "# Project website: https://phishing.army \n" \
                     "# ===================================================\n" % datetime.utcnow().strftime(
        "%a, %d %b %Y %H:%M:%S UTC")

    bannerwildcard = "# \n" \
                     "# Phishing Army | The Blocklist to filter Phishing \n" \
                     "# \n" \
                     "# Last Update: %s\n" \
                     "# \n" \
                     "# This is the wildcard version (WARNING, it is not compatible with PiHole!), for the normal/extend version go to the project website.\n" \
                     "# \n" \
                     "# Project website: https://phishing.army \n" \
                     "# ===================================================\n" % datetime.utcnow().strftime(
        "%a, %d %b %Y %H:%M:%S UTC")

    # Procedo a scrivere il contenuto

    with open("/home/phisarmy/public_html/download/phishing_army_blocklist.txt", "w") as f:

        f.write("%s\n" % banner)

        for item in BlockList2:
            f.write("%s\n" % item)

    with open("/home/phisarmy/public_html/download/phishing_army_blocklist_extended.txt", "w") as f:

        f.write("%s\n" % bannerextended)

        for item in BlockListExtended2:
            f.write("%s\n" % item)

    with open("/home/phisarmy/public_html/download/phishing_army_blocklist_wildcard.txt", "w") as f:

        f.write("%s\n" % bannerwildcard)

        for item in BlockListWildcard2:
            f.write("*.%s\n" % item)


if __name__ == "__main__":
    main()
