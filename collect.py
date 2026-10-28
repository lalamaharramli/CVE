"""Data collection: one function per online source.

Every collector follows the same contract:

    - it makes a real network request with a timeout
    - it never raises; it returns a dictionary instead
    - the dictionary always has an "ok" key (True / False) and an "error" key

That way one dead source cannot end the whole run.

THE SHARED RESULT SHAPE
-----------------------
Everything the collectors return is merged into one dictionary that the rest
of the program uses. Agreeing this shape up front is what lets people work on
different files at the same time:

    {
        "cve_id":     "CVE-2017-0144",
        "summary":    "The SMBv1 server in Microsoft Windows ...",
        "published":  "2017-03-17",
        "cwe":        ["CWE-119"],
        "products":   ["cpe:2.3:o:microsoft:windows_7:..."],
        "cvss":       {"version": "3.1", "score": 8.1,
                       "severity": "HIGH", "vector": "CVSS:3.1/AV:N/..."},
        "exploit":    {"available": True,
                       "entries": [{"id": "41891", "title": "...",
                                    "url": "https://www.exploit-db.com/exploits/41891"}]},
        "in_kev":     True,
        "kev_action": "Apply updates per vendor instructions.",
        "references": [{"url": "...", "tags": ["Patch"], "score": 40}],
        "priority":   "P1",
        "sources":    {"NVD": "ok", "Exploit-DB": "ok", "CISA KEV": "ok"},
    }
"""

import csv
import json
import os
import time

import requests
from bs4 import BeautifulSoup

# MA - Shared network settings. A timeout on every request is what stops the
# MA - tool hanging forever when a source is slow or down.
TIMEOUT = 20
HEADERS = {"User-Agent": "Group3-CVE-Report-Tool/1.0 (student project)"}
CACHE_DIR = "cache"

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EXPLOITDB_CSV = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
EXPLOITDB_PAGE = "https://www.exploit-db.com/exploits/"
KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
VULMON_PAGE = "https://vulmon.com/vulnerabilitydetails?qid="

# MA - Big files (the Exploit-DB catalogue is several MB) are downloaded once
# MA - and kept in a cache folder, so re-running the tool is fast.
CACHE_MAX_AGE = 60 * 60 * 24  # one day, in seconds


# MA - Download a large file once and reuse it on later runs
def cached_download(url, filename):
    """Return the text of url, using a local cached copy when one is fresh.

    Returns None if the file could not be downloaded and no cache exists.
    """
    path = os.path.join(CACHE_DIR, filename)

    if os.path.exists(path):
        age = time.time() - os.path.getmtime(path)
        if age < CACHE_MAX_AGE:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                return handle.read()

    try:
        response = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
    except requests.RequestException:
        response = None

    if response is not None and response.status_code == 200:
        if not os.path.isdir(CACHE_DIR):
            os.makedirs(CACHE_DIR)
        with open(path, "w", encoding="utf-8", errors="replace") as handle:
            handle.write(response.text)
        return response.text

    # MA - Download failed. A stale cache is better than nothing at all.
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    return None


# LM - Fetch the official NVD record for one CVE
def from_nvd(cve_id):
    """Fetch description, CVSS metrics and references from the NVD API.

    The NVD web page is rendered by JavaScript, so scraping the HTML gives
    nothing useful. The public JSON API returns the same data and needs no
    API key.
    """
    result = {"ok": False, "error": "", "summary": "", "published": "",
              "metrics": {}, "cwe": [], "products": [], "references": []}

    try:
        response = requests.get(NVD_API, params={"cveId": cve_id},
                                headers=HEADERS, timeout=TIMEOUT)
    except requests.Timeout:
        result["error"] = "NVD did not respond in time"
        return result
    except requests.RequestException as exc:
        result["error"] = "could not reach NVD ({})".format(type(exc).__name__)
        return result

    if response.status_code == 404:
        result["error"] = "NVD has no record for this CVE"
        return result
    if response.status_code != 200:
        result["error"] = "NVD returned HTTP {}".format(response.status_code)
        return result

    try:
        payload = response.json()
    except ValueError:
        result["error"] = "NVD returned something that was not valid JSON"
        return result

    # LM - An empty "vulnerabilities" list means the CVE does not exist. That
    # LM - is a clean "not found", not an error to raise.
    items = payload.get("vulnerabilities", [])
    if not items:
        result["error"] = "NVD has no record for this CVE"
        return result

    # LM - The record we want is the first entry, under its "cve" key
    cve = items[0].get("cve", {})

    # LM - Take the first English description
    for entry in cve.get("descriptions", []):
        if entry.get("lang") == "en":
            result["summary"] = entry.get("value", "")
            break

    result["published"] = cve.get("published", "")[:10]
    result["metrics"] = cve.get("metrics", {})

    # LM - Collect the CWE weakness IDs, skipping duplicates
    for weakness in cve.get("weaknesses", []):
        for entry in weakness.get("description", []):
            value = entry.get("value", "")
            if value.startswith("CWE-") and value not in result["cwe"]:
                result["cwe"].append(value)

    # LM - Walk the configurations tree to list affected products (CPE strings)
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria", "")
                if criteria and criteria not in result["products"]:
                    result["products"].append(criteria)

    # LM - Keep each reference URL together with the tags NVD gave it; the
    # LM - analysis file uses those tags to rank the references later.
    for reference in cve.get("references", []):
        result["references"].append({
            "url": reference.get("url", ""),
            "tags": reference.get("tags", []),
        })

    result["ok"] = True
    return result


# FM - Look the CVE up in the Exploit-DB catalogue
def from_exploitdb(cve_id):
    """Search Exploit-DB for a public exploit for this CVE.

    The exploit-db.com search page is behind a bot filter that blocks plain
    HTTP clients, so we use the official published catalogue instead: the
    Exploit-DB git repository holds a CSV of every exploit and the CVE IDs it
    covers. We download that once and search it locally.
    """
    result = {"ok": False, "error": "", "available": False, "entries": []}

    text = cached_download(EXPLOITDB_CSV, "files_exploits.csv")
    if text is None:
        result["error"] = "could not download the Exploit-DB catalogue"
        return result

    wanted = cve_id.upper()
    seen_ids = []

    # FM - Parse the CSV row by row and keep the rows whose "codes" column
    # FM - contains the CVE ID as a case-insensitive substring.
    try:
        reader = csv.DictReader(text.splitlines())
        for row in reader:
            codes = (row.get("codes") or "").upper()
            if wanted not in codes:
                continue
            edb_id = row.get("id", "")
            # FM - The catalogue can list the same exploit id in more than one
            # FM - row, so skip an id we have already recorded.
            if edb_id in seen_ids:
                continue
            seen_ids.append(edb_id)
            result["entries"].append({
                "id": edb_id,
                "title": row.get("description", ""),
                "type": row.get("type", ""),
                "platform": row.get("platform", ""),
                "date": row.get("date_published", ""),
                "verified": row.get("verified", "") == "1",
                "url": EXPLOITDB_PAGE + edb_id,
            })
    except csv.Error:
        result["error"] = "the Exploit-DB catalogue could not be parsed"
        return result

    result["ok"] = True
    result["available"] = len(result["entries"]) > 0
    return result


# ZZ - Check whether CISA lists the CVE as actively exploited
def from_kev(cve_id):
    """Check the CISA Known Exploited Vulnerabilities catalogue.

    A CVE in this catalogue is being used in real attacks right now, which
    matters more for urgency than the CVSS score on its own.
    """
    result = {"ok": False, "error": "", "listed": False,
              "action": "", "due_date": ""}

    text = cached_download(KEV_JSON, "kev.json")
    if text is None:
        result["error"] = "could not download the CISA KEV catalogue"
        return result

    try:
        payload = json.loads(text)
    except ValueError:
        result["error"] = "the KEV catalogue was not valid JSON"
        return result

    # ZZ - Scan the catalogue for this CVE by its cveID field
    for entry in payload.get("vulnerabilities", []):
        if entry.get("cveID", "").upper() == cve_id.upper():
            result["listed"] = True
            result["action"] = entry.get("requiredAction", "")
            result["due_date"] = entry.get("dueDate", "")
            break

    result["ok"] = True
    return result


# ZZ - Scrape the Vulmon page for extra context
def from_vulmon(cve_id):
    """Scrape Vulmon for a short extra summary.

    This is the one source we parse out of raw HTML with BeautifulSoup. It is
    a nice-to-have: if the page layout changes or the site is unreachable, the
    report is still produced without it.
    """
    result = {"ok": False, "error": "", "title": "", "text": ""}

    try:
        response = requests.get(VULMON_PAGE + cve_id,
                                headers=HEADERS, timeout=TIMEOUT)
    except requests.RequestException:
        result["error"] = "could not reach Vulmon"
        return result

    if response.status_code != 200:
        result["error"] = "Vulmon returned HTTP {}".format(response.status_code)
        return result

    soup = BeautifulSoup(response.text, "html.parser")

    heading = soup.find("h1")
    if heading is not None:
        result["title"] = heading.get_text(strip=True)

    # ZZ - Take the longest paragraph on the page; on Vulmon that is the
    # ZZ - vulnerability description rather than page furniture.
    longest = ""
    for paragraph in soup.find_all("p"):
        body = paragraph.get_text(strip=True)
        if len(body) > len(longest):
            longest = body
    result["text"] = longest[:800]

    if not result["title"] and not result["text"]:
        result["error"] = "nothing usable found on the Vulmon page"
        return result

    result["ok"] = True
    return result