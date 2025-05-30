#!/usr/bin/env python3
# This file is part of Phishing Army.
#
# Phishing Army was made with ♥ by Andrea Draghetti
#
# This file may be licensed under the terms of of the
# GNU General Public License Version 3 (the ``GPL'').
#
import os
import requests
import tldextract

tldcache = tldextract.TLDExtract()

timeout_connection = 120
header_desktop = {"User-Agent": "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)",
                  "Accept-Language": "it,en-US;q=0.7,en;q=0.3"}

white_list = []

# Source: https://s3.amazonaws.com/alexa-static/top-1m.csv.zip
f = open("./list/top-1m.csv", "r")

for line in f:
    if line:
        line = line.rstrip()
        line = line.split(",")[1]
        line = line.lower()
        registered_domain = tldcache(line).top_domain_under_public_suffix
        white_list.append(registered_domain)

f.close()

# Source: ND
f = open("./list/business_domains.txt", "r")

for line in f:
    if line:
        line = line.rstrip()
        line = line.lower()
        registered_domain = tldcache(line).top_domain_under_public_suffix
        white_list.append(registered_domain)

f.close()

# Source: https://github.com/anudeepND/whitelist
urls_download = ["https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt",
                 "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/referral-sites.txt",
                 "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/optional-list.txt"]

for url in urls_download:
    r = requests.get(url, headers=header_desktop, timeout=timeout_connection)

    if r.status_code == 200:
        for line in r.iter_lines(decode_unicode=True):
            if line:
                line = line.rstrip()
                line = line.lower()
                registered_domain = tldcache(line).top_domain_under_public_suffix
                if registered_domain:
                    white_list.append(registered_domain)

if white_list:
    white_list = list(set(white_list))

for domain in white_list:
    if domain:
        print(domain)
