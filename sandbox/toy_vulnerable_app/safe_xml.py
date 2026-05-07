"""
Negative-control XML file for scout-xxe E2E testing.

Includes the FND-PATH-0003 calibration pattern: ET.fromstring is safe on
modern CPython and MUST NOT fire scout-xxe.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
import xml.sax
from xml.dom import minidom


# Calibration check: ET.fromstring is safe on CPython 3.7.1+. MUST NOT FLAG.
def parse_etree(blob):
    return ET.fromstring(blob)


# defusedxml — recommended replacement, MUST NOT FLAG.
def parse_defused(blob):
    import defusedxml.ElementTree as DET
    return DET.fromstring(blob)


# minidom — safer wrapper around expatbuilder, MUST NOT FLAG.
def parse_minidom(blob):
    return minidom.parseString(blob)


# SAX with default features — defaults to entity resolution off in modern
# CPython on most platforms; we don't fire on the bare default.
def parse_sax_default(blob):
    return xml.sax.make_parser().parse(blob)


# lxml with safe default — modern lxml >= 4.6 default is safe.
def parse_lxml_default(blob):
    from lxml import etree
    return etree.fromstring(blob, etree.XMLParser())
