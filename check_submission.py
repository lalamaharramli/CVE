"""Pre-submission structure check.

Run this from inside your project folder before you zip it:

    python check_submission.py

It checks the things the automated grading pass depends on: required files
present, naming conventions, self-assessment word counts, attribution marks,
and that nothing is in the folder that should not be. It does NOT check whether
your tool works or grade it in any way - that is what the marker does.

Standard library only, so it runs anywhere.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

JUNK_DIRS = {".venv", "venv", "env", "__pycache__", ".git", ".idea", ".vscode",
             "node_modules", ".pytest_cache", ".mypy_cache", "__MACOSX"}
JUNK_FILES = {".DS_Store", "Thumbs.db", "desktop.ini"}
MAX_FILE_MB = 10

SA_RE = re.compile(r"^([A-Za-z\-']+)_([A-Za-z\-']+)_SelfAssessment\.txt$")
ATTRIB_RE = re.compile(r"#\s*([A-Z][A-Za-z]{0,3})\s*(?:-|--|:|\u2013|\u2014)\s*\S")
# Tokens that match the initials shape but are not people. Kept in step with the
# grading tool, so what you see here is what the marker's tooling sees.
NOT_INITIALS = {
    "TODO", "FIXME", "XXX", "HACK", "BUG", "NOTE", "WARN", "DONE", "WIP", "REF",
    "SEE", "USE", "SET", "GET", "RUN", "ADD", "FIX", "NEW", "OLD", "API", "URL",
    "CVE", "NVD", "HTTP", "JSON", "HTML", "CSS", "MAIN", "TEST", "STEP", "PART",
    "INFO", "TIP", "TBD", "NB", "EG", "IE", "OK",
}
README_SECTIONS = {
    "description": r"#\s*\w|description|about|overview",
    "dependencies": r"depend|requirement|install|librar|package",
    "run instructions": r"usage|how to run|running|python\s+main\.py|execut",
    "members and roles": r"member|team|contributor|author|role|responsib",
}

problems: list[str] = []
warnings: list[str] = []
notes: list[str] = []


def fail(msg):
    problems.append(msg)


def warn(msg):
    warnings.append(msg)


def ok(msg):
    notes.append(msg)


def student_files(pattern="*"):
    return [p for p in ROOT.rglob(pattern)
            if p.is_file() and not (set(p.relative_to(ROOT).parts) & JUNK_DIRS)]


def check_layout():
    for path in ROOT.rglob("*"):
        parts = set(path.relative_to(ROOT).parts)
        if path.is_dir() and path.name in JUNK_DIRS:
            warn(f"delete before zipping: {path.relative_to(ROOT)}/")
        if path.is_file() and path.name in JUNK_FILES:
            warn(f"delete before zipping: {path.relative_to(ROOT)}")
        if path.is_file() and not (parts & JUNK_DIRS):
            size_mb = path.stat().st_size / (1024 * 1024)
            if size_mb > MAX_FILE_MB:
                warn(f"{path.relative_to(ROOT)} is {size_mb:.1f} MB - do not submit large files")


def check_entrypoint():
    main = ROOT / "main.py"
    if not main.is_file():
        fail("main.py is missing from the top level. The grading run executes 'python main.py'.")
        return
    text = main.read_text(encoding="utf-8", errors="replace")
    if not re.search(r"if\s+__name__\s*==\s*['\"]__main__['\"]", text):
        warn("main.py has no `if __name__ == \"__main__\":` guard.")
    if "input(" not in text and not re.search(r"argparse|sys\.argv", text):
        fail("main.py neither prompts with input() nor reads a command line argument. "
             "The grading run feeds the CVE ID on standard input.")
    else:
        ok("main.py is present and takes input")
    if re.search(r"['\"][A-Za-z]:[\\/]|/home/|/Users/", text):
        warn("main.py looks like it contains an absolute path. Write output relative to the "
             "current directory - the grading environment is not your machine.")


def check_python():
    py = [p for p in student_files("*.py") if p.name != Path(__file__).name]
    if not py:
        fail("no .py files found")
        return [], {}
    bad = []
    initials: dict[str, int] = {}
    for path in py:
        rel = path.relative_to(ROOT)
        text = path.read_text(encoding="utf-8", errors="replace")
        try:
            ast.parse(text)
        except SyntaxError as exc:
            bad.append(f"{rel}:{exc.lineno}: {exc.msg}")
        marked = False
        for line in text.splitlines():
            m = ATTRIB_RE.search(line)
            if m and not re.search(r"https?://|#!/", line):
                key = m.group(1).upper()
                if key in NOT_INITIALS:
                    continue
                initials[key] = initials.get(key, 0) + 1
                marked = True
        if not marked:
            warn(f"{rel} carries no '# <initials> - <comment>' attribution marks")
    if bad:
        for b in bad:
            fail(f"syntax error: {b}")
    else:
        ok(f"{len(py)} .py file(s), all parse")
    if "XX" in initials:
        fail("the placeholder initials 'XX' are still in the code - replace them with real initials")
    if not initials:
        fail("no '# <initials> - <comment>' attribution marks found anywhere. "
             "The brief requires them and individual marks depend on them.")
    else:
        ok("attribution marks: " + ", ".join(f"{k}={v}" for k, v in sorted(initials.items())))
    return py, initials


def check_requirements():
    req = ROOT / "requirements.txt"
    if not req.is_file():
        fail("requirements.txt is missing")
        return
    pkgs = [ln.strip() for ln in req.read_text(encoding="utf-8", errors="replace").splitlines()
            if ln.strip() and not ln.strip().startswith("#")]
    if not pkgs:
        fail("requirements.txt is empty")
    elif len(pkgs) > 60:
        warn(f"requirements.txt lists {len(pkgs)} packages - this looks like a pip freeze of "
             "your whole system. List only what your tool imports.")
    else:
        ok(f"requirements.txt lists {len(pkgs)} package(s)")


def check_readme():
    readme = ROOT / "README.md"
    if not readme.is_file():
        other = [p.name for p in ROOT.glob("*") if p.stem.lower() == "readme"]
        fail("README.md is missing" + (f" (found {other} instead - it must be README.md)" if other else ""))
        return
    low = readme.read_text(encoding="utf-8", errors="replace").lower()
    missing = [name for name, rx in README_SECTIONS.items() if not re.search(rx, low)]
    if "[project name]" in low or "[first last]" in low:
        fail("README.md still contains template placeholders in square brackets")
    if missing:
        fail("README.md is missing required section(s): " + ", ".join(missing))
    else:
        ok("README.md has all four required sections")


def check_self_assessments(initials):
    found, misnamed = [], []
    for path in student_files("*.txt"):
        name = path.name
        if not ("self" in name.lower() and "assess" in name.lower()):
            continue
        m = SA_RE.match(name)
        if not m:
            misnamed.append(name)
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        words = len(text.split())
        ini = (m.group(1)[0] + m.group(2)[0]).upper()
        found.append((name, ini, words))
        if "RENAME THIS FILE" in text:
            fail(f"{name} still contains the template instructions")
        if not 100 <= words <= 200:
            fail(f"{name} is {words} words - the brief requires 100-200")
    for name in misnamed:
        fail(f"{name} does not follow [FirstName]_[LastName]_SelfAssessment.txt")
    if not found:
        fail("no self-assessment files found. One per group member is required.")
        return
    ok(f"{len(found)} self-assessment(s): " + ", ".join(f"{n} ({w}w)" for n, _i, w in found))

    sa_initials = {i for _n, i, _w in found}
    for ini in sorted(sa_initials - set(initials)):
        warn(f"{ini} filed a self-assessment but has no attributed code")
    for ini in sorted(set(initials) - sa_initials):
        warn(f"{ini} has attributed code but no self-assessment")


def main():
    print(f"Checking {ROOT.name}/ ...\n")
    check_layout()
    check_entrypoint()
    _py, initials = check_python()
    check_requirements()
    check_readme()
    check_self_assessments(initials)

    for line in notes:
        print(f"  ok    {line}")
    for line in warnings:
        print(f"  warn  {line}")
    for line in problems:
        print(f"  FAIL  {line}")

    print()
    if problems:
        print(f"{len(problems)} problem(s) to fix before submitting, "
              f"{len(warnings)} warning(s).")
        return 1
    if warnings:
        print(f"Structure is acceptable, with {len(warnings)} warning(s) worth a look.")
    else:
        print("Structure looks good.")
    print("\nThis only checks structure. Now verify it RUNS: unzip your submission into an "
          "empty folder, make a fresh virtual environment, pip install -r requirements.txt, "
          "and run python main.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
