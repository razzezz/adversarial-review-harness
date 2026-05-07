"""
Planted XXE bugs for scout-xxe E2E testing.

One function per scout-xxe pattern. The expected pattern ID is in the
`# pattern:` comment above each function. Do not "fix" these.
"""

from __future__ import annotations

from lxml import etree
import xml.sax
from xml.sax import handler
from xml.dom import expatbuilder


# pattern: lxml_resolve_entities
def parse_lxml_blob(blob: bytes):
    parser = etree.XMLParser(resolve_entities=True)
    return etree.fromstring(blob, parser)


# pattern: sax_external_entities
def parse_sax_stream(blob):
    parser = xml.sax.make_parser()
    parser.setFeature(handler.feature_external_ges, True)
    return parser.parse(blob)


# pattern: expatbuilder_direct
def parse_expat(blob: str):
    return expatbuilder.parseString(blob)
