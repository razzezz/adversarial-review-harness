"""Unit tests for scout-xxe's AST-based detection primitives."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
DETECTOR = REPO_ROOT / ".claude" / "tools" / "scout_xxe_detect.py"


def _load():
    spec = importlib.util.spec_from_file_location("scout_xxe_detect", DETECTOR)
    assert spec and spec.loader, f"cannot load {DETECTOR}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _scan(src: str, tmp_path: Path):
    mod = _load()
    p = tmp_path / "x.py"
    p.write_text(src)
    return mod.scan_project(tmp_path)


# ---------------------------------------------------------------------------
# Pattern 1: lxml_resolve_entities
# ---------------------------------------------------------------------------


def test_lxml_xmlparser_resolve_entities_true_flags(tmp_path):
    findings = _scan(
        "from lxml import etree\n"
        "def parse(blob):\n"
        "    p = etree.XMLParser(resolve_entities=True)\n"
        "    return etree.fromstring(blob, p)\n",
        tmp_path,
    )
    assert any(f.pattern == "lxml_resolve_entities" for f in findings)


def test_lxml_xmlparser_default_does_not_flag(tmp_path):
    # Modern lxml (>= 4.6) defaults to resolve_entities=False; we don't fire
    # on the bare default. Note: detecting the lxml<4.6 case via pyproject
    # is out of scope for this v1 (left as future work).
    findings = _scan(
        "from lxml import etree\n"
        "def parse(blob):\n"
        "    p = etree.XMLParser()\n"
        "    return etree.fromstring(blob, p)\n",
        tmp_path,
    )
    assert not any(f.pattern == "lxml_resolve_entities" for f in findings)


def test_resolve_entities_false_does_not_flag(tmp_path):
    findings = _scan(
        "from lxml import etree\n"
        "def parse(blob):\n"
        "    p = etree.XMLParser(resolve_entities=False)\n"
        "    return etree.fromstring(blob, p)\n",
        tmp_path,
    )
    assert not any(f.pattern == "lxml_resolve_entities" for f in findings)


def test_etree_fromstring_alone_does_not_flag(tmp_path):
    # Calibration check: xml.etree.ElementTree is safe on modern CPython.
    findings = _scan(
        "import xml.etree.ElementTree as ET\n"
        "def parse(blob):\n"
        "    return ET.fromstring(blob)\n",
        tmp_path,
    )
    assert not findings


def test_lxml_xmlparser_resolve_entities_via_dict_does_not_flag(tmp_path):
    # Edge: we don't follow dict spreading; AST-direct kwarg is the contract.
    findings = _scan(
        "from lxml import etree\n"
        "def parse(blob):\n"
        "    cfg = {'resolve_entities': True}\n"
        "    p = etree.XMLParser(**cfg)\n"
        "    return etree.fromstring(blob, p)\n",
        tmp_path,
    )
    assert not any(f.pattern == "lxml_resolve_entities" for f in findings)


# ---------------------------------------------------------------------------
# Pattern 2: sax_external_entities
# ---------------------------------------------------------------------------


def test_sax_feature_external_ges_true_flags(tmp_path):
    findings = _scan(
        "import xml.sax\n"
        "from xml.sax import handler\n"
        "def parse(blob):\n"
        "    p = xml.sax.make_parser()\n"
        "    p.setFeature(handler.feature_external_ges, True)\n"
        "    return p.parse(blob)\n",
        tmp_path,
    )
    assert any(f.pattern == "sax_external_entities" for f in findings)


def test_sax_feature_external_pes_true_flags(tmp_path):
    findings = _scan(
        "import xml.sax\n"
        "from xml.sax import handler\n"
        "def parse(blob):\n"
        "    p = xml.sax.make_parser()\n"
        "    p.setFeature(handler.feature_external_pes, True)\n"
        "    return p.parse(blob)\n",
        tmp_path,
    )
    assert any(f.pattern == "sax_external_entities" for f in findings)


def test_sax_default_make_parser_does_not_flag(tmp_path):
    findings = _scan(
        "import xml.sax\n"
        "def parse(blob):\n"
        "    p = xml.sax.make_parser()\n"
        "    return p.parse(blob)\n",
        tmp_path,
    )
    assert not any(f.pattern == "sax_external_entities" for f in findings)


def test_sax_feature_external_ges_false_does_not_flag(tmp_path):
    findings = _scan(
        "import xml.sax\n"
        "from xml.sax import handler\n"
        "def parse(blob):\n"
        "    p = xml.sax.make_parser()\n"
        "    p.setFeature(handler.feature_external_ges, False)\n"
        "    return p.parse(blob)\n",
        tmp_path,
    )
    assert not any(f.pattern == "sax_external_entities" for f in findings)


def test_sax_set_feature_via_string_literal_flags(tmp_path):
    # Edge: a literal feature URI can be used instead of the handler attribute.
    findings = _scan(
        "import xml.sax\n"
        "def parse(blob):\n"
        "    p = xml.sax.make_parser()\n"
        "    p.setFeature('http://xml.org/sax/features/external-general-entities', True)\n"
        "    return p.parse(blob)\n",
        tmp_path,
    )
    assert any(f.pattern == "sax_external_entities" for f in findings)


# ---------------------------------------------------------------------------
# Pattern 3: expatbuilder_direct
# ---------------------------------------------------------------------------


def test_expatbuilder_parsestring_flags(tmp_path):
    findings = _scan(
        "from xml.dom import expatbuilder\n"
        "def parse(blob):\n"
        "    return expatbuilder.parseString(blob)\n",
        tmp_path,
    )
    assert any(f.pattern == "expatbuilder_direct" for f in findings)


def test_expatbuilder_parse_flags(tmp_path):
    findings = _scan(
        "from xml.dom import expatbuilder\n"
        "def parse(path):\n"
        "    return expatbuilder.parse(path)\n",
        tmp_path,
    )
    assert any(f.pattern == "expatbuilder_direct" for f in findings)


def test_minidom_parsestring_does_not_flag(tmp_path):
    # minidom is the safer wrapper around expatbuilder.
    findings = _scan(
        "from xml.dom import minidom\n"
        "def parse(blob):\n"
        "    return minidom.parseString(blob)\n",
        tmp_path,
    )
    assert not any(f.pattern == "expatbuilder_direct" for f in findings)


def test_defusedxml_parsestring_does_not_flag(tmp_path):
    findings = _scan(
        "import defusedxml.minidom\n"
        "def parse(blob):\n"
        "    return defusedxml.minidom.parseString(blob)\n",
        tmp_path,
    )
    assert not findings


def test_expatbuilder_imported_but_not_called_does_not_flag(tmp_path):
    # Edge: import without call.
    findings = _scan(
        "from xml.dom import expatbuilder  # noqa\n"
        "def f():\n"
        "    pass\n",
        tmp_path,
    )
    assert not findings
