"""Group3 CVE Report Tool - entry point.

Takes a CVE ID, collects data about it from NVD, Exploit-DB, the CISA KEV
catalogue and Vulmon, works out how urgent it is, prints a formatted report,
opens the best references in a browser and saves the report to disk.

Usage:
    python main.py
    python main.py CVE-2017-0144
"""

import datetime
import re
import sys
import webbrowser

import analyse
import collect
import report

# LM - A CVE ID is the four-letter prefix, a four digit year, then four or more
# LM - digits. Anchoring the pattern at both ends is what rejects input like
# LM - "CVE-2017-0144; whoami" instead of quietly accepting the first part.
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,7}$")

MAX_ATTEMPTS = 3

RED = "31"
GREEN = "32"


# MA - Wrap text in a terminal colour, but only when writing to a real
# MA - terminal, so a redirected log file does not fill with escape codes.
def paint(text, code):
    """Return text wrapped in an ANSI colour, or unchanged if output is piped."""
    if not sys.stdout.isatty():
        return text
    return "\033[{}m{}\033[0m".format(code, text)


# LM - Validate and normalise the CVE ID supplied by the user
def validate(raw):
    """Return a normalised CVE ID, or None if the input is malformed."""
    if raw is None:
        return None

    cleaned = raw.strip().upper()
    # LM - Collapse any internal whitespace so "CVE - 2017 - 0144" is not
    # LM - silently treated as valid, but "CVE-2017-0144  " is.
    cleaned = " ".join(cleaned.split())

    if not cleaned:
        return None
    if not CVE_PATTERN.match(cleaned):
        return None
    return cleaned


# LM - Prompt the user for a CVE ID, re-asking on bad input
def prompt_for_cve():
    """Ask for a CVE ID, re-prompting on invalid input. Return None to give up."""
    attempts = 0

    while attempts < MAX_ATTEMPTS:
        attempts = attempts + 1
        try:
            raw = input("Enter a CVE ID (for example CVE-2017-0144): ")
        except (EOFError, KeyboardInterrupt):
            print(paint("\nNo input received. Exiting.", RED))
            return None

        cve = validate(raw)
        if cve:
            return cve

        print(paint("  '{}' is not a valid CVE ID.".format(raw.strip()), RED))
        print("  Expected format: CVE-YYYY-NNNN, e.g. CVE-2021-44228")

    print(paint("Too many invalid attempts. Exiting.", RED))
    return None


# MA - Run every collector and record which ones worked
def gather(cve_id):
    """Collect from all sources. Returns the merged data dictionary."""
    data = {
        "cve_id": cve_id,
        "generated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "sources": {},
    }

    print("  Querying NVD ...")
    nvd = collect.from_nvd(cve_id)
    data["sources"]["NVD"] = "ok" if nvd["ok"] else nvd["error"]

    if not nvd["ok"]:
        # MA - No NVD record means no description, no score and no references.
        # MA - There is nothing worth reporting, so stop here rather than
        # MA - printing an empty form.
        data["fatal"] = nvd["error"]
        return data

    data["summary"] = nvd["summary"]
    data["published"] = nvd["published"]
    data["cwe"] = nvd["cwe"]
    data["products"] = nvd["products"]
    data["cvss"] = analyse.parse_cvss(nvd["metrics"])

    print("  Checking Exploit-DB ...")
    exploitdb = collect.from_exploitdb(cve_id)
    data["sources"]["Exploit-DB"] = "ok" if exploitdb["ok"] else exploitdb["error"]
    data["exploit"] = {"available": exploitdb["available"],
                       "entries": exploitdb["entries"]}

    print("  Checking CISA KEV ...")
    kev = collect.from_kev(cve_id)
    data["sources"]["CISA KEV"] = "ok" if kev["ok"] else kev["error"]
    data["in_kev"] = kev["listed"]
    data["kev_action"] = kev["action"]

    print("  Checking Vulmon ...")
    vulmon = collect.from_vulmon(cve_id)
    data["sources"]["Vulmon"] = "ok" if vulmon["ok"] else vulmon["error"]
    if vulmon["ok"] and not data["summary"]:
        data["summary"] = vulmon["text"]

    print("  Verifying reference links ...")
    data["references"] = analyse.rank_references(nvd["references"])

    return data


# ZZ - Open the top references in the user's browser
def open_references(references):
    """Open each reference in a browser tab, printing them as a fallback."""
    if not references:
        print("No references to open.")
        return

    print("\nOpening {} reference(s) in your browser:".format(len(references)))
    for reference in references:
        print("  {}".format(reference["url"]))
        try:
            webbrowser.open(reference["url"])
        except Exception:
            # ZZ - A grading machine or server may have no browser at all. The
            # ZZ - URLs are printed above either way, so this is not fatal.
            pass


# LM - Drive collection, analysis, reporting and file output
def main(argv=None):
    """Run the tool end to end. Return the process exit code."""
    argv = sys.argv[1:] if argv is None else argv

    if argv:
        cve = validate(argv[0])
        if not cve:
            print(paint("'{}' is not a valid CVE ID.".format(argv[0].strip()), RED))
            print("Expected format: CVE-YYYY-NNNN, e.g. CVE-2021-44228")
            return 1
    else:
        cve = prompt_for_cve()

    if not cve:
        return 1

    print("\nCollecting data for {} ...".format(cve))
    data = gather(cve)

    if data.get("fatal"):
        print(paint("\nCould not build a report for {}: {}".format(cve, data["fatal"]), RED))
        print("Check the ID is correct and that you are online.")
        return 1

    priority, reason = analyse.classify_risk(
        data["cvss"]["score"],
        data["exploit"]["available"],
        data["in_kev"],
    )
    data["priority"] = priority
    data["priority_reason"] = reason
    data["priority_meaning"] = analyse.priority_meaning(priority)
    data["remediation"] = analyse.find_remediation(data["references"],
                                                   data.get("kev_action", ""))

    print("\n" + report.render(data))

    open_references(data["references"])

    written = report.save(data)
    if written:
        print(paint("\nReport saved to:", GREEN))
        for path in written:
            print("  {}".format(path))
    else:
        print(paint("\nThe report could not be saved to disk.", RED))

    return 0


if __name__ == "__main__":
    sys.exit(main())