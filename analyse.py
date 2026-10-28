"""Analysis: normalise what the sources returned, then prioritise it.

Nothing in this file touches the network except the link check at the bottom.
Every other function takes plain data and returns plain data, so it can be
tested without an internet connection.
"""

import requests

TIMEOUT = 10
HEADERS = {"User-Agent": "Group3-CVE-Report-Tool/1.0 (student project)"}

# MA - How useful a reference is, judged by the tag NVD gives it. A patch or a
# MA - vendor advisory tells you how to fix the problem, so it outranks a news
# MA - article or a mailing list post.
TAG_SCORES = {
    "Patch": 50,
    "Vendor Advisory": 40,
    "Mitigation": 35,
    "Technical Description": 30,
    "Exploit": 25,
    "Third Party Advisory": 20,
    "US Government Resource": 15,
    "VDB Entry": 10,
    "Issue Tracking": 10,
}

MAX_REFERENCES = 5


# FM - Pull the CVSS score and severity out of the raw NVD metrics block
def parse_cvss(metrics):
    """Return version, base score, severity label and vector string.

    NVD may return CVSS v4.0, v3.1, v3.0 and v2.0 for the same CVE. We prefer
    the newest available and fall back down the list. Older CVEs often only
    have a v2 score, so the fallback is not optional.
    """
    result = {"version": "", "score": None, "severity": "UNKNOWN", "vector": ""}

    order = ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]

    for key in order:
        entries = metrics.get(key, [])
        if not entries:
            continue

        entry = entries[0]
        data = entry.get("cvssData", {})

        result["version"] = data.get("version", "")
        result["score"] = data.get("baseScore")
        result["vector"] = data.get("vectorString", "")

        # FM - In CVSS v3 and v4 the severity label lives inside cvssData; in
        # FM - v2 it sits one level up. Check both rather than assuming.
        severity = data.get("baseSeverity")
        if not severity:
            severity = entry.get("baseSeverity")

        if severity:
            result["severity"] = severity.upper()
        elif result["score"] is not None:
            result["severity"] = severity_from_score(result["score"])

        return result

    return result


# FM - Turn a bare number into a severity word when the source did not give one
def severity_from_score(score):
    """Return the standard CVSS severity label for a base score."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


# ZZ - Derive an action priority from severity and real-world exploitability
def classify_risk(score, exploit_available, in_kev):
    """Return a priority code and the plain-English reason for it.

    The rule that matters: a vulnerability someone has already published
    working code for is more urgent than a slightly higher-scoring one that
    nobody knows how to attack yet. A CVSS score describes how bad the damage
    would be; an available exploit describes how likely it is to happen.
    """
    # ZZ - No score at all is its own first case, before any threshold test.
    if score is None:
        if in_kev or exploit_available:
            return "P1", "no CVSS score, but the vulnerability is exploited or has a public exploit"
        return "P3", "no CVSS score available to judge severity"

    if in_kev:
        return "P1", "listed by CISA as exploited in the wild"

    if exploit_available and score >= 7.0:
        return "P1", "high severity with a public exploit available"

    if score >= 9.0:
        return "P1", "critical severity"

    if exploit_available and score >= 4.0:
        return "P2", "public exploit available for a medium severity issue"

    if score >= 7.0:
        return "P2", "high severity, no public exploit found"

    if exploit_available:
        return "P3", "public exploit available, but low severity"

    if score >= 4.0:
        return "P3", "medium severity"

    return "P4", "low severity"


# ZZ - Explain what a priority code means in the report
def priority_meaning(priority):
    """Return a one-line description of a priority code."""
    meanings = {
        "P1": "Patch immediately",
        "P2": "Patch in the current cycle",
        "P3": "Schedule for a normal maintenance window",
        "P4": "Track, no urgent action",
    }
    return meanings.get(priority, "Unclassified")


# ZZ - The key function .sort() uses to order references by score
def reference_score(reference):
    """Return the numeric score of a reference, for sorting."""
    return reference["score"]


# ZZ - Score every reference so the most useful ones come first
def score_references(references):
    """Return the references sorted best first, with a score attached."""
    scored = []
    seen_urls = []

    for reference in references:
        url = reference.get("url", "")
        if not url.startswith("http"):
            continue
        # ZZ - NVD sometimes lists the same URL as two separate references, so
        # ZZ - drop a URL we have already scored.
        if url in seen_urls:
            continue
        seen_urls.append(url)

        points = 0
        for tag in reference.get("tags", []):
            points = points + TAG_SCORES.get(tag, 5)

        scored.append({"url": url, "tags": reference.get("tags", []),
                       "score": points})

    scored.sort(key=reference_score, reverse=True)
    return scored


# ZZ - Confirm a link actually works before we put it in the report
def link_is_alive(url):
    """Return True if the URL answers without a client or server error.

    Some servers reject HEAD requests, so a failed HEAD is retried as a GET
    before we give up on the link.
    """
    try:
        response = requests.head(url, headers=HEADERS, timeout=TIMEOUT,
                                 allow_redirects=True)
        if response.status_code < 400:
            return True
        response = requests.get(url, headers=HEADERS, timeout=TIMEOUT,
                                allow_redirects=True, stream=True)
        return response.status_code < 400
    except requests.RequestException:
        return False


# MA - Pick the five best working references
def rank_references(references, limit=MAX_REFERENCES, verify=True,
                    max_checks=15):
    """Return up to `limit` verified references, most useful first.

    Five is a deliberate cap. A CVE can carry forty references, most of them
    duplicates of the same advisory. Opening forty browser tabs is not a
    report.
    """
    scored = score_references(references)
    chosen = []
    checked = 0

    for reference in scored:
        if len(chosen) >= limit:
            break
        if not verify:
            chosen.append(reference)
            continue
        if checked >= max_checks:
            break
        checked = checked + 1
        if link_is_alive(reference["url"]):
            reference["verified"] = True
            chosen.append(reference)

    # MA - If every link check failed (offline, or a firewall in the way) we
    # MA - still report the best-scoring links rather than an empty section.
    if not chosen and scored:
        for reference in scored[:limit]:
            reference["verified"] = False
            chosen.append(reference)

    return chosen


# FM - Pull remediation advice out of whatever the sources gave us
def find_remediation(references, kev_action):
    """Return a short remediation note built from the available evidence."""
    if kev_action:
        return kev_action

    for reference in references:
        if "Patch" in reference.get("tags", []):
            return "A vendor patch is listed. See: {}".format(reference["url"])

    for reference in references:
        if "Vendor Advisory" in reference.get("tags", []):
            return "Follow the vendor advisory: {}".format(reference["url"])

    # FM - Last, check whether any reference at all is tagged as a mitigation.
    for reference in references:
        for tag in reference.get("tags", []):
            if tag == "Mitigation":
                return "Mitigation guidance is available in the references below."

    return "No specific remediation was published. Check the vendor advisory."
