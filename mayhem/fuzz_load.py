#! /usr/bin/env python3
import atheris
import sys
import fuzz_helpers

from py_pdf_parser.exceptions import PDFParserError
from pdfminer.pdfparser import PDFSyntaxError
from pdfminer.psparser import PSException

with atheris.instrument_imports(include=['pdfminer', 'py_pdf_parser']):
    import py_pdf_parser.loaders

def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    try:
        with fdp.ConsumeMemoryFile(all_data=True) as f:
            py_pdf_parser.loaders.load(f)
    except (PDFParserError, PDFSyntaxError, PSException):
        return -1

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
