#! /usr/bin/env python3
import atheris
import sys
import fuzz_helpers

from io import BytesIO
from contextlib import contextmanager
from py_pdf_parser.exceptions import PDFParserError
from pdfminer.pdfparser import PDFSyntaxError
from pdfminer.psparser import PSException

@contextmanager
def nostdout():
    save_stdout = sys.stdout
    save_stderr = sys.stderr
    sys.stdout = BytesIO()
    sys.stderr = BytesIO()
    yield
    sys.stdout = save_stdout
    sys.stderr = save_stderr

with atheris.instrument_imports(include=['pdfminer', 'py_pdf_parser']):
    import py_pdf_parser.loaders

def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    try:
        with fdp.ConsumeMemoryFile(all_data=True) as f, nostdout():
            py_pdf_parser.loaders.load(f)
    except (PDFParserError, PDFSyntaxError, PSException, TypeError, ValueError, KeyError):
        return -1

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
