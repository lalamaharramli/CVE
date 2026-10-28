"""Report generation: render the analysed data and write it to disk.

Layout is done with format strings and alignment specifiers, not by counting
spaces by hand. Every section copes with its field being missing, because a
source that failed is a normal outcome, not a crash.
"""

import os
import textwrap

WIDTH = 78
LABEL = 16


# FM - Fill in a placeholder when a source gave us nothing
def value_or(value, fallback="not available"):
    """Return the value as text, or a readable fallback when it is empty."""
    if value is None:
        return fallback
    text = str(value).strip()
    if not text:
        return fallback
    return text


# FM - Turn a true/false into the words yes or no for the report
def yes_no(value):
    """Return "yes" for a true value and "no" for a false one."""
    if value:
        return "yes"
    return "no"


# KH - Show the CVSS base score to one decimal place, or a fallback
def format_score(cvss):
    """Return the base score as text like "8.1", or "not available"."""
    score = cvss.get("score")
    if score is None:
        return "not available"
    return "{:.1f}".format(score)


# KH - Draw a section heading for the plain text report
def heading(title):
    """Return a section heading padded out to the report width."""
    return "\n{}\n{}\n".format(title.upper(), "-" * WIDTH)


# KH - Wrap long prose so the report stays readable in a terminal
def wrap(text, indent=""):
    """Return text wrapped to the report width."""
    if not text:
        return indent + "not available"
    lines = textwrap.wrap(text, width=WIDTH - len(indent))
    wrapped = []
    for line in lines:
        wrapped.append(indent + line)
    return "\n".join(wrapped)


# KH - Build the plain text report body using format strings
def render(data):
    """Return the full report as one formatted string."""
    cvss = data.get("cvss", {})
    exploit = data.get("exploit", {})
    parts = []

    # KH - Header block
    parts.append("=" * WIDTH)
    parts.append("{:^{width}}".format("CVE VULNERABILITY REPORT", width=WIDTH))
    parts.append("{:^{width}}".format(data.get("cve_id", "unknown"), width=WIDTH))
    parts.append("=" * WIDTH)
    parts.append("{:<{label}}{}".format("Generated:", data.get("generated", ""),
                                        label=LABEL))
    parts.append("{:<{label}}{}".format("Published:",
                                        value_or(data.get("published")),
                                        label=LABEL))

    parts.append(heading("Summary"))
    parts.append(wrap(data.get("summary", "")))

    # KH - Severity block: every field goes through value_or so a missing
    # KH - metric prints "not available" instead of the word None.
    parts.append(heading("Severity (CVSS)"))
    parts.append("{:<{label}}{}".format("CVSS version:",
                                        value_or(cvss.get("version")),
                                        label=LABEL))
    parts.append("{:<{label}}{}".format("Base score:", format_score(cvss),
                                        label=LABEL))
    parts.append("{:<{label}}{}".format("Severity:",
                                        value_or(cvss.get("severity")),
                                        label=LABEL))
    parts.append("{:<{label}}{}".format("Vector:",
                                        value_or(cvss.get("vector")),
                                        label=LABEL))

    parts.append(heading("Action priority"))
    parts.append("{:<{label}}{} - {}".format("Priority:",
                                             data.get("priority", "?"),
                                             data.get("priority_meaning", ""),
                                             label=LABEL))
    parts.append("{:<{label}}{}".format("Reason:", data.get("priority_reason", ""),
                                        label=LABEL))
    parts.append("{:<{label}}{}".format("In CISA KEV:",
                                        yes_no(data.get("in_kev")),
                                        label=LABEL))

    # KH - Public exploits block
    parts.append(heading("Public exploits"))
    entries = exploit.get("entries", [])
    if entries:
        parts.append("{} entry/entries found on Exploit-DB.\n".format(len(entries)))
        for entry in entries[:10]:
            parts.append("  [{}] {}".format(value_or(entry.get("id")),
                                            value_or(entry.get("title"))))
            parts.append("      {:<12}{}".format("platform:",
                                                 value_or(entry.get("platform"))))
            parts.append("      {:<12}{}".format("verified:",
                                                 yes_no(entry.get("verified"))))
            parts.append("      {:<12}{}".format("url:", value_or(entry.get("url"))))
            parts.append("")
    else:
        parts.append("No public exploit was found on Exploit-DB.")

    parts.append(heading("Remediation"))
    parts.append(wrap(data.get("remediation", "")))

    # KH - Affected products block, capped at eight lines
    parts.append(heading("Affected products (sample)"))
    products = data.get("products", [])
    if products:
        for product in products[:8]:
            parts.append("  - {}".format(product))
        if len(products) > 8:
            parts.append("  ... and {} more".format(len(products) - 8))
    else:
        parts.append("  not available")

    parts.append(heading("Weaknesses"))
    cwes = data.get("cwe", [])
    if cwes:
        parts.append("  " + ", ".join(cwes))
    else:
        parts.append("  not available")

    # KH - Top references block
    parts.append(heading("Top references"))
    references = data.get("references", [])
    if references:
        position = 0
        for reference in references:
            position = position + 1
            tags = ", ".join(reference.get("tags", []))
            if not tags:
                tags = "untagged"
            if reference.get("verified"):
                checked = "verified"
            else:
                checked = "unchecked"
            parts.append("  {}. {}".format(position, reference["url"]))
            parts.append("     {:<10}{}  ({})".format("tags:", tags, checked))
    else:
        parts.append("  no working references were found")

    parts.append(heading("Sources"))
    for name, status in data.get("sources", {}).items():
        parts.append("  {:<14}{}".format(name + ":", status))

    parts.append("\n" + "=" * WIDTH)
    parts.append("Report produced by the Group3 CVE Report Tool.")
    parts.append("=" * WIDTH)

    return "\n".join(parts)


# KH - Build a Markdown version of the same report
def render_markdown(data):
    """Return the report in Markdown, with a table for the severity block."""
    cvss = data.get("cvss", {})
    exploit = data.get("exploit", {})

    lines = []
    lines.append("# CVE Report: {}".format(data.get("cve_id", "unknown")))
    lines.append("")
    lines.append("*Generated {}*".format(data.get("generated", "")))
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(value_or(data.get("summary")))
    lines.append("")

    # KH - Severity as a Markdown table
    lines.append("## Severity")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("|---|---|")
    lines.append("| CVSS version | {} |".format(value_or(cvss.get("version"))))
    lines.append("| Base score | {} |".format(format_score(cvss)))
    lines.append("| Severity | {} |".format(value_or(cvss.get("severity"))))
    lines.append("| Vector | `{}` |".format(value_or(cvss.get("vector"))))
    lines.append("| Priority | **{}** - {} |".format(data.get("priority", "?"),
                                                     data.get("priority_meaning", "")))
    lines.append("| In CISA KEV | {} |".format(yes_no(data.get("in_kev"))))
    lines.append("")
    lines.append("Reason: {}".format(data.get("priority_reason", "")))
    lines.append("")

    lines.append("## Public exploits")
    lines.append("")
    entries = exploit.get("entries", [])
    if entries:
        for entry in entries[:10]:
            lines.append("- [{}]({}) - {}".format(value_or(entry.get("id")),
                                                  value_or(entry.get("url")),
                                                  value_or(entry.get("title"))))
    else:
        lines.append("No public exploit was found on Exploit-DB.")
    lines.append("")

    lines.append("## Remediation")
    lines.append("")
    lines.append(value_or(data.get("remediation")))
    lines.append("")

    lines.append("## Top references")
    lines.append("")
    references = data.get("references", [])
    if references:
        for reference in references:
            tags = ", ".join(reference.get("tags", []))
            if not tags:
                tags = "untagged"
            lines.append("- <{}> - {}".format(reference["url"], tags))
    else:
        lines.append("No working references were found.")
    lines.append("")

    lines.append("## Sources")
    lines.append("")
    for name, status in data.get("sources", {}).items():
        lines.append("- **{}**: {}".format(name, status))
    lines.append("")

    return "\n".join(lines)


# KH - Write the report to reports/ inside the current working directory
def save(data, out_dir="reports"):
    """Write the report as .txt and .md. Return the list of paths written."""
    if not os.path.isdir(out_dir):
        try:
            os.makedirs(out_dir)
        except OSError:
            out_dir = "."

    stem = data.get("cve_id", "report").replace("/", "_")
    written = []

    files = [(stem + "_report.txt", render(data)),
             (stem + "_report.md", render_markdown(data))]

    for name, text in files:
        path = os.path.join(out_dir, name)
        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(text)
            written.append(path)
        except OSError as exc:
            print("Could not write {}: {}".format(path, exc))

    return written
