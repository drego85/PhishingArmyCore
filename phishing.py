#!/usr/bin/python3
import os
import sys
import gzip
import json
import Config
import logging
import requests
import tldextract
from datetime import datetime, timedelta

timeoutconnection = 120
headerdesktop = {"User-Agent": "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)",
                 "Accept-Language": "it"}

headerphishtank = {"User-Agent": "Phishtank/phishingarmy",
                 "Accept-Language": "it"}

tldcache = tldextract.TLDExtract(cache_file="./.tld_set")

WhiteList = []
BlockList = []
BlockListExtended = []
BlockListWildcard = []

# Inizializzo i LOG
logging.basicConfig(filename="phishing.log",
                    format="%(asctime)s - %(funcName)10s():%(lineno)s - %(levelname)s - %(message)s",
                    level=logging.INFO)


def phishtank():
    urldownload = "https://data.phishtank.com/data/" + Config.phishtanktoken + "online-valid.json.gz"

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

                if registered_domain and registered_domain not in WhiteList:
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
                url = url.lower()

                registered_domain = tldcache(url).registered_domain
                sub_domain = tldcache(url).subdomain

                if sub_domain:
                    full_domain = sub_domain + "." + registered_domain
                else:
                    full_domain = registered_domain

                if registered_domain and registered_domain not in WhiteList:
                    BlockList.append(full_domain)
                    BlockListExtended.append(full_domain)
                    BlockListWildcard.append(registered_domain)
                    if full_domain != registered_domain:
                        BlockListExtended.append(registered_domain)

    except Exception as e:
        logging.error(e, exc_info=True)
        raise


def phishfindr():
    urlList = [
        "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE-NOW.txt",
        "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE-TODAY.txt",
        "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-NEW-last-hour.txt",
        "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-NEW-today.txt",
        "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt"]

    # La seguente lista è stata esclusa poichè troppo ampia da elaborare
    # https://github.com/mitchellkrogza/Phishing.Database/raw/master/phishing-links-ACTIVE.txt

    for urldownload in urlList:
        try:
            r = requests.get(urldownload, headers=headerdesktop, timeout=timeoutconnection)

            if r.status_code is 200:
                for line in r.iter_lines():
                    url = line.decode("utf-8")
                    url = url.lower()

                    registered_domain = tldcache(url).registered_domain
                    sub_domain = tldcache(url).subdomain

                    if sub_domain:
                        full_domain = sub_domain + "." + registered_domain
                    else:
                        full_domain = registered_domain

                    if registered_domain and registered_domain not in WhiteList:
                        BlockList.append(full_domain)
                        BlockListExtended.append(full_domain)
                        BlockListWildcard.append(registered_domain)
                        if full_domain != registered_domain:
                            BlockListExtended.append(registered_domain)

        except Exception as e:
            logging.error(e, exc_info=True)
            raise


def whitelist():
    try:
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
    except Exception as e:
        logging.error(e, exc_info=True)
        pass

    try:
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
    except Exception as e:
        logging.error(e, exc_info=True)
        pass

    try:
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
    except Exception as e:
        logging.error(e, exc_info=True)
        pass

    try:
        # Source https://s3.amazonaws.com/alexa-static/top-1m.csv.zip
        f = open("./list/alexa-top-1m.txt", "r")

        for line in f:
            if line:
                line = line.rstrip()
                line = line.lower()
                analyzeddomain = tldcache(line).registered_domain
                if analyzeddomain:
                    WhiteList.append(analyzeddomain)
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
                analyzeddomain = tldcache(line).registered_domain
                if analyzeddomain:
                    WhiteList.append(analyzeddomain)
        f.close()

    except Exception as e:
        logging.error(e, exc_info=True)
        pass


def main():
    # Carico le Whitelist
    whitelist()
    logging.info("Download di %s dominii da WhiteList" % len(WhiteList))

    # Carico le segnalazioni convalidate di Phishtank
    phishtank()

    # Carico le segnalazioni convalidate da OpenPhish
    openphish()

    # Carico le segnalazioni convalida da PhishFindR
    phishfindr()

    # Eliminio doppioni e ordino le liste generate
    BlockListSorted = sorted(set(BlockList))
    BlockListExtendedSorted = sorted(set(BlockListExtended))
    BlockListWildcardSorted = sorted(set(BlockListWildcard))

    logging.info("Generata la Blocklist contenente %s dominii" % len(BlockListSorted))
    logging.info("Generata la Blocklist Extended contenente %s dominii" % len(BlockListExtendedSorted))

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

    bannerextended = "# \n" \
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

    bannerwildcard = "# \n" \
                     "# Phishing Army | The Blocklist to filter Phishing \n" \
                     "# \n" \
                     "# Last Update: %s\n" \
                     "# \n" \
                     "# This is the wildcard version, it is not compatible with Pi-Hole.\n" \
                     "# \n" \
                     "# Project website: https://phishing.army \n" \
                     "# \n" \
                     "# This work is licensed under a Creative Commons Attribution-NonCommercial 4.0 International License. \n" \
                     "# ======================================================================================================\n" % datetime.utcnow().strftime(
        "%a, %d %b %Y %H:%M:%S UTC")

    # Procedo a scrivere il contenuto
    with open(Config.outputdirectory + "phishing_army_blocklist.txt", "w") as f:

        f.write("%s\n" % banner)

        for item in BlockListSorted:
            f.write("%s\n" % item)

    with open(Config.outputdirectory + "phishing_army_blocklist_extended.txt", "w") as f:

        f.write("%s\n" % bannerextended)

        for item in BlockListExtendedSorted:
            f.write("%s\n" % item)

    with open(Config.outputdirectory + "phishing_army_blocklist_wildcard.txt", "w") as f:

        f.write("%s\n" % bannerwildcard)

        for item in BlockListWildcardSorted:
            f.write("*.%s\n" % item)


if __name__ == "__main__":
    main()
