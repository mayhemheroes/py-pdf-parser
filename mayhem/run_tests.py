#!/usr/bin/python3
"""run_tests.py — RUN py-pdf-parser's own loaders known-answer suite and print a parseable summary.

Invoked via the `/mayhem/pdf-tests` ELF launcher (NOT directly), so the verify-repo sabotage oracle
can neuter the launcher and prove the test oracle is behavioral.

It runs tests/test_loaders.py — real known-answer cases that load the bundled PDFs through
py_pdf_parser.loaders.load / load_file and assert the parsed document EXACTLY: the element count of
image.pdf is 1 (or 2 with all_texts), test.pdf loads to a PDFDocument, and a wrong password raises
PDFPasswordIncorrect. This exercises the very code path the fuzzer drives. A no-op / "exit(0)" /
behavior-altering patch to py_pdf_parser cannot pass it. (This suite needs only pdfminer.six — it
does NOT import tests/base.py, so it avoids the GUI/visualise deps tkinter/matplotlib/wand.)

It writes a JUnit XML, parses the counts, and prints one line:

    RUNTESTS tests=<n> passed=<p> failed=<f> skipped=<s>

Exit 0 iff failed == 0. mayhem/test.sh parses that line into a CTRF report.
"""
from __future__ import annotations

import sys
import xml.etree.ElementTree as ET

import pytest

XML = "/tmp/py-pdf-parser-junit.xml"
TESTS_FILE = "/mayhem/tests/test_loaders.py"


def main() -> int:
    pytest.main(["-q", "-p", "no:cacheprovider", TESTS_FILE, "--junitxml", XML])

    root = ET.parse(XML).getroot()
    suites = root.findall("testsuite") or ([root] if root.tag == "testsuite" else [])
    if not suites:
        print("RUNTESTS tests=0 passed=0 failed=1 skipped=0")
        return 1

    tests = failed = skipped = 0
    for s in suites:
        tests += int(s.get("tests", 0))
        failed += int(s.get("failures", 0)) + int(s.get("errors", 0))
        skipped += int(s.get("skipped", 0))
    passed = tests - failed - skipped

    print(f"RUNTESTS tests={tests} passed={passed} failed={failed} skipped={skipped}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
