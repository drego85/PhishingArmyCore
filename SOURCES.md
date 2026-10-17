# Sources and acknowledgements

Phishing Army is an aggregator and openly acknowledges the independent projects that provide its phishing intelligence. Its contribution is the balanced aggregation, normalization, false-positive reduction, format conversion and reliable distribution of those sources.

Phishing Army consumes current source snapshots only. It does not paginate into historical data and does not carry indicators forward between builds. A failed source is isolated and retried at the next scheduled generation.

## Active sources

| Source | Endpoint and window | Authentication and policy |
| --- | --- | --- |
| PhishTank, operated by Cisco Talos Intelligence Group | `online-valid.csv.gz` | Application key in the provider-defined URL; only records marked `verified=yes` and `online=yes` are accepted |
| OpenPhish | Public community feed | Public; current feed snapshot |
| CERT.PL | `https://hole.cert.pl/domains/v2/domains.txt` | Public; active domains from the latest six months. Removed entries disappear from the feed |
| Phishunt | `https://phishunt.io/feed.txt` | Public; current feed snapshot |
| urlscan.io | Search API, 1,000 newest results | API key; public scans tagged `phishing` or `malicious`, HTTP status 200; no date cutoff; only `task.url` is used |
| PhishStats | Search API | Public anonymous access; newest 100 records only |
| StalkPhish | `/api/v1/last` | Token; live window and maximum results are determined by the subscribed plan (currently Free) |
| URLAbuse, operated by NetSSR | `https://urlabuse.com/get_record_by_rowid`, 100 newest records | Registered email and token; no `rowid`, pagination or retained cursor; only records with `rtype=phishing` are accepted; one request per three-hour build, without immediate retries (provider recommends at least five minutes between calls); [CC BY 4.0](https://urlabuse.com/terms.html) attribution required |
| AntiPhish.org | `/v1/search` | Public; records are locally restricted to `threat_type=phishing`; use is authorized by the AntiPhish.org team |

## Whitelist inputs

The reviewed general whitelist uses [Tranco](https://tranco-list.eu/), the maintained [anudeepND allowlists](https://github.com/anudeepND/whitelist) and the operator's `list/business_domains.txt`. These are false-positive protection inputs, not phishing intelligence feeds. The active ranking ID, approval date and hashes are recorded in `list/global_whitelist.metadata.json`; updates are manual. Ranking a shared service root does not protect all of its tenants. Candidate roots that conflict with the current public blocklist are excluded before operator review.

### Shared-platform boundaries

The offline private Public Suffix List and `list/shared_subdomain_services.txt` identify tenant namespaces. A shared boundary itself remains protected. A general-whitelist entry at or above that boundary does not authorize every tenant. Only tenant namespaces supported by current feed indicators are considered for blocking; neither sibling tenants nor platform parents are inferred. An explicitly allowlisted tenant protects its own namespace, and personal-whitelist entries retain precedence.

The following additional boundaries are supported by public provider documentation:

| Tenant boundary | Public documentation |
| --- | --- |
| `mybluehost.me` | [Bluehost temporary account domains](https://www.bluehost.com/help/article/about-domain-names) |
| `cloudwaysapps.com` | [Cloudways application staging domains](https://support.cloudways.com/en/articles/5120711-how-to-clone-your-server) |
| `cloudclusters.net` | [Cloud Clusters per-site default domains](https://www.cloudclusters.io/docs/runtime/Adding%20Your%20Domain1608099880.html) |
| `weebly.com` | [Weebly free website subdomains](https://www.weebly.com/app/help/us/en/topics/custom-domains-vs-free-subdomains) |
| `myclickfunnels.com` | [ClickFunnels workspace subdomains](https://support.myclickfunnels.com/docs/how-to-add-a-new-workspace-1) |
| `hosted.phplist.com` | [phpList account-specific hosted installations](https://www.phplist.com/knowledgebase/how-to-add-sub-account/) |
| `up.railway.app` | [Railway service domains](https://docs.railway.com/networking/domains/working-with-domains) |
| `storage.googleapis.com` | [Google Cloud Storage bucket hostname and path-style endpoints](https://docs.cloud.google.com/storage/docs/request-endpoints) |

The phpList and Railway exceptions are deliberately restricted to `hosted.phplist.com` and `up.railway.app`; they do not turn the providers' entire institutional domains into tenant namespaces. Monthly whitelist candidate checks use these same boundaries, so a safe platform-parent ranking is not rejected merely because one hosted tenant is blocked. Ordinary non-shared namespaces and explicitly ranked blocked tenants still require review.

Shared storage nodes, regional endpoints and URL shorteners are not classified as independent tenant hosts merely because they have subdomains. Path-level abuse on a multi-user hostname cannot be isolated by a DNS blocklist and needs separate operator review.

Google Cloud Storage is a reviewed exception with two documented addressing styles: `storage.googleapis.com/BUCKET/OBJECT` and `BUCKET.storage.googleapis.com/OBJECT`. The exact `storage.googleapis.com` endpoint is protected as a shared boundary; path-style reports must not block every bucket. Reported bucket hostnames remain independently blockable even when Tranco ranks `googleapis.com` or `storage.googleapis.com`. The Discord attachment-upload bucket `discord-attachments-uploads-prd.storage.googleapis.com` is explicitly personally allowlisted because its shared user files cannot be isolated at DNS level. This narrow exception does not allowlist sibling buckets or all of Google Cloud Storage.

`link.me` is a path-based link-in-bio platform: individual creator pages share the same hostname. It is explicitly allowed in `list/personal_whitelist.txt` and classified in `list/path_shared_services.txt` because blocking one reported page at DNS level would also block unrelated legitimate pages.

`biolink.website` is similarly a [link-in-bio platform](https://biolink.website/) with user profiles addressed through URL paths. It is explicitly allowed in `list/personal_whitelist.txt` and classified in `list/path_shared_services.txt` to avoid blocking unrelated creators and businesses because of individual abusive profiles. This is a DNS-level collateral-damage decision, not a certification that every profile or linked destination is safe. Other similarly named domains are not automatically allowlisted.

`firebasestorage.googleapis.com` is the shared Firebase Storage endpoint, with independent buckets and objects addressed through URL paths, as documented in [Firebase file downloads](https://firebase.google.com/docs/storage/web/download-files). It is explicitly allowed in `list/personal_whitelist.txt` and classified in `list/path_shared_services.txt`. Phishing or redirect abuse of individual resources does not justify a DNS block against every Firebase Storage user. This exception is not a safety certification for its contents and does not allowlist other `googleapis.com` services or Google Cloud Storage bucket hostnames.

`www.duckdns.org` is explicitly allowed in `list/personal_whitelist.txt` because it is the provider's website and [documented dynamic DNS update API](https://www.duckdns.org/spec.jsp), not a user-assigned tenant. The private Public Suffix List still identifies `duckdns.org` as a shared boundary: reported user hostnames remain independently blockable. The personal exception must not be broadened to all of `duckdns.org`.

## Local harmless test indicators

`amiprotected.it` is owned by the Phishing Army operator and hosts a harmless static filtering-test landing page. The apex and `www.amiprotected.it` are intentionally added on every build without a network fetch, API credentials, historical cursor or upstream phishing classification. They are separate from the nine active intelligence providers above and must never be reported to them as real phishing.

Both hostnames are declared in `phishing_army.builder.TEST_DOMAINS` and added to the canonical set before rendering every format. Popularity ranking inputs do not disable them, but the personal whitelist retains precedence, including protection of an explicitly allowed descendant. Banners label their purpose, the manifest lists included test domains in `test_domains`, and live lookup distinguishes `local_test_domains` from provider matches. Neither test satisfies source-success counts, raw-provider indicator counts or publication-size guards.

## Deliberately excluded

- Phishing.Database / PhishFindR: removed because of recurring false positives and unreliable current coverage.
- Stop Forum Spam: its purpose and freshness do not align closely enough with a phishing-only list.
- IsItPhishing: no suitable current public feed was identified.
- urlscan.io tags `sinking-yachts` and `#phishing`: intentionally excluded. The query has no six-hour cutoff because older live phishing reports remain useful.

No resource domains, redirect targets or other urlscan.io page dependencies are inferred automatically. This avoids turning a single malicious page into a block against shared infrastructure.

## Attribution and terms

Each provider remains the owner of its data and service. Phishing Army's public usage notice does not grant or sublicense rights over upstream data. Organizations and commercial users are responsible for reviewing the current terms, attribution requirements, rate limits and redistribution permissions of every active source and for obtaining any authorization required for their own use case.

URLAbuse data and services are licensed under CC BY 4.0 unless otherwise noted. Phishing Army credits URLAbuse and NetSSR, links to `https://urlabuse.com/`, filters its current 100-record API window to phishing, and does not imply endorsement.

Voluntary donations to Phishing Army support development, generation, hosting and distribution. They do not purchase upstream licensing rights, priority support, a service-level agreement, endorsement or influence over blocking decisions. API credentials must never be committed, logged or embedded in generated feeds.

Removing, obscuring or minimizing source attribution is not an accepted project practice. The website, repository documentation and generated-feed banner must always provide a clear path to this source list.
