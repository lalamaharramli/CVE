# CVE Report Tool

A command-line tool that takes a CVE ID, collects information about that
vulnerability from four public sources, works out how urgently it needs to be
patched, prints a formatted report, opens the five most useful references in a
browser, and saves the report to disk as both plain text and Markdown.

Built by team Group3 for the Azerbaijan Cybersecurity Center final project.

**What goes in:** one CVE ID, e.g. `CVE-2017-0144`.
**What comes out:** a printed report, up to five browser tabs, and two files in
`reports/`.

## Sources used

| Source | What we take from it | How we reach it |
|---|---|---|
| NIST NVD | description, CVSS metrics, CWE, affected products, references | official JSON API |
| Exploit-DB | whether a public exploit exists, and its ID and URL | official published CSV catalogue |
| CISA KEV | whether the CVE is being exploited in the wild right now | official JSON feed |
| Vulmon | extra descriptive text | HTML page parsed with BeautifulSoup |

Two notes on honest engineering here:

- The NVD **web page** is rendered by JavaScript, so scraping its HTML returns
  nothing useful. We use the NVD JSON API instead, which serves the same data.
  The public rate limit is five requests per rolling thirty seconds, which is
  ample for one CVE at a time.
- The **exploit-db.com search page is behind a bot filter** that rejects plain
  HTTP clients. Rather than trying to defeat that, we use the catalogue that
  Exploit-DB itself publishes: a CSV in their public git repository listing
  every exploit and the CVE IDs it covers. It is downloaded once and cached in
  `cache/`, then searched locally.

## Dependencies

- Python 3.10 or newer
- `requests` - all HTTP requests to the four sources
- `beautifulsoup4` - parsing the Vulmon HTML page

```
python -m venv .venv
.venv\Scripts\activate          # Windows
source .venv/bin/activate       # macOS / Linux
pip install -r requirements.txt
```

## Instructions for running the project

```
python main.py
python main.py CVE-2017-0144
```

With no argument the tool prompts for a CVE ID and re-asks up to three times if
the input is malformed. With an argument it validates it and exits with a clear
message if it is wrong.

The tool then prints the report to the terminal, opens up to five verified
reference links in your default browser, and writes two files:

```
reports/CVE-2017-0144_report.txt
reports/CVE-2017-0144_report.md
```

A `cache/` folder is created on first run to hold the Exploit-DB catalogue and
the KEV feed so that later runs are fast. It is safe to delete.

## How the priority is decided

A CVSS score says how bad the damage would be. It does not say how likely an
attack is. A vulnerability with a published working exploit is more urgent than
a slightly higher-scoring one that nobody knows how to attack yet, so the
priority weighs both:

| Condition | Priority | Meaning |
|---|---|---|
| Listed in CISA KEV | P1 | Patch immediately |
| Score >= 7.0 with a public exploit | P1 | Patch immediately |
| Score >= 9.0 | P1 | Patch immediately |
| Public exploit, score >= 4.0 | P2 | Patch in the current cycle |
| Score >= 7.0, no exploit | P2 | Patch in the current cycle |
| Score >= 4.0 | P3 | Schedule for maintenance |
| Anything lower | P4 | Track, no urgent action |

References are capped at five. A CVE can carry forty of them, most repeating the
same advisory, and forty browser tabs is not a report. They are scored by the
tag NVD assigns (a patch or vendor advisory beats a news article), checked with
an HTTP request to confirm they are not broken, and the best five are opened.

## List of group members and their roles

| Member | Initials | Responsible for |
|---|---|---|
| Aslan Mammadzada | MA | `gather` and `paint` in `main.py`, the shared download cache and network settings in `collect.py` (`cached_download`), and the reference tag-score table plus the five-reference cap in `analyse.py` (`rank_references`) |
| Lala Maharramli | LM | `from_nvd` in `collect.py` — calling the NVD JSON API and pulling the description, metrics, CWEs, affected products and references out of the response — plus CVE ID validation, prompting and the `main()` entry point in `main.py` (`validate`, `prompt_for_cve`, `main`) |
| Fuad Mammadli | FM | `from_exploitdb` in `collect.py`, `parse_cvss` / `severity_from_score` and `find_remediation` in `analyse.py`, and the `value_or` / `yes_no` helpers in `report.py` |
| Zara Zahidova | ZZ | `from_kev` and `from_vulmon` in `collect.py`, `classify_risk` / `priority_meaning` in `analyse.py`, the reference scoring and link check in `analyse.py` (`score_references`, `reference_score`, `link_is_alive`), and opening references in the browser in `main.py` (`open_references`) |
| Khadija Huseynzada | KH | most of `report.py` — `render`, `render_markdown`, `save` and the remaining format-string helpers |

The initials column matches the `# XY - comment` attribution marks in the
source, which the automated grading tool greps for.

### How the sections were assigned

The beginner sections were matched to how hard the code is to read aloud in an
oral defense, not to how many lines it is:

| Section | Owner | Why it sits here |
|---|---|---|
| `from_nvd`, `validate` / `prompt_for_cve` / `main` | Lala | `from_nvd` is the hardest beginner piece: four nested loops walking a deep JSON tree (`configurations` → `nodes` → `cpeMatch`) and several separate error paths. The `main.py` input handling and the `main()` wiring are lighter and pair naturally with owning the first source the tool calls. |
| `from_exploitdb`, `parse_cvss`, `find_remediation`, `value_or` / `yes_no` | Fuad | Medium: the `csv` module plus the download cache, and the CVSS version fallback with the severity label living in two different places. `find_remediation` and the two `report.py` helpers are short, self-contained additions. |
| `from_kev`, `from_vulmon`, `classify_risk`, `score_references` / `reference_score` / `link_is_alive`, `open_references` | Zara | Lighter pieces spread across files: one download and one loop for KEV, the BeautifulSoup scrape for Vulmon, the `if` / `elif` priority ladder, the reference scoring pass, and the browser-open loop. Each is small and readable on its own. |
| `render`, `render_markdown`, `save` | Khadija | Longest by line count but the shallowest to read: the same `str.format()` pattern repeated section after section, and `render_markdown` is a near-copy of `render`. |

## Additional instructions or comments

- Every network call has a timeout and is wrapped so that a source being down
  degrades the report rather than crashing the tool. The `SOURCES` section at
  the bottom of every report states exactly which sources answered and which
  did not.
- If NVD cannot be reached or has no record for the ID, the tool says so and
  exits cleanly instead of printing an empty report.
- Reports are written relative to the current working directory, never to an
  absolute path.