"""Unit tests for scout-template's AST-based detection primitives.

Mirrors scout-sqli's detector pattern.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
DETECTOR = REPO_ROOT / ".claude" / "tools" / "scout_template_detect.py"


def _load():
    spec = importlib.util.spec_from_file_location("scout_template_detect", DETECTOR)
    assert spec and spec.loader, f"cannot load {DETECTOR}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Positive: jinja2 Environment().from_string(user_input).
# ---------------------------------------------------------------------------


def test_jinja2_from_string_fstring_flags(tmp_path):
    mod = _load()
    src = tmp_path / "app.py"
    src.write_text(
        "from jinja2 import Environment\n"
        "def render(name):\n"
        "    return Environment().from_string(f'Hello {name}').render()\n"
    )
    findings = mod.scan_project(tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == "CWE-94"
    assert "from_string" in f.sink
    assert f.poc_applicable is True


def test_jinja2_Template_user_input_flags(tmp_path):
    mod = _load()
    src = tmp_path / "app.py"
    src.write_text(
        "from jinja2 import Template\n"
        "def render(user_tpl):\n"
        "    return Template(user_tpl).render()\n"
    )
    findings = mod.scan_project(tmp_path)
    # Bare Name(user_tpl) as argument — the detector flags Template()/
    # from_string() where the first arg is a Name referencing an enclosing
    # function parameter (potentially tainted).
    assert len(findings) >= 1


# ---------------------------------------------------------------------------
# Positive: render_template_string with interpolation.
# ---------------------------------------------------------------------------


def test_render_template_string_fstring_flags(tmp_path):
    mod = _load()
    src = tmp_path / "app.py"
    src.write_text(
        "from flask import render_template_string\n"
        "def view(name):\n"
        "    return render_template_string(f'Hello {name}')\n"
    )
    findings = mod.scan_project(tmp_path)
    assert len(findings) == 1
    assert "render_template_string" in findings[0].sink


# ---------------------------------------------------------------------------
# Positive: mako.
# ---------------------------------------------------------------------------


def test_mako_template_user_input_flags(tmp_path):
    mod = _load()
    src = tmp_path / "app.py"
    src.write_text(
        "from mako.template import Template\n"
        "def render(body):\n"
        "    return Template(body).render()\n"
    )
    findings = mod.scan_project(tmp_path)
    assert len(findings) >= 1


# ---------------------------------------------------------------------------
# Negative: constant template source.
# ---------------------------------------------------------------------------


def test_constant_template_no_finding(tmp_path):
    mod = _load()
    src = tmp_path / "app.py"
    src.write_text(
        "from jinja2 import Environment\n"
        "TEMPLATE = 'Hello {{ name }}'\n"
        "def render(name):\n"
        "    return Environment().from_string(TEMPLATE).render(name=name)\n"
    )
    findings = mod.scan_project(tmp_path)
    # TEMPLATE is a module-level Name binding — the detector only flags
    # f-strings / % / + / .format() or function-parameter Name refs.
    # TEMPLATE is module-level, not a function parameter, so zero findings.
    assert findings == []


# ---------------------------------------------------------------------------
# Handler-name heuristic: upgrades severity to critical.
# ---------------------------------------------------------------------------


def test_handler_name_upgrades_to_critical(tmp_path):
    mod = _load()
    src = tmp_path / "app.py"
    src.write_text(
        "from jinja2 import Environment\n"
        "class Handler:\n"
        "    def _handle_greet(self, source):\n"
        "        return Environment().from_string(source).render()\n"
    )
    findings = mod.scan_project(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == "critical"


# ---------------------------------------------------------------------------
# End-to-end: toy-app _handle_greet fixture (planted in Task 10).
# ---------------------------------------------------------------------------


def test_toy_app_greet_handler_pattern(tmp_path):
    mod = _load()
    src = tmp_path / "app.py"
    src.write_text(
        "class ToyHandler:\n"
        "    def _handle_greet(self):\n"
        "        template_source = self.rfile.read().decode('utf-8')\n"
        "        from jinja2 import Environment\n"
        "        return Environment().from_string(template_source).render()\n"
    )
    findings = mod.scan_project(tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == "CWE-94"
    assert f.severity == "critical"
    assert f.poc_applicable is True
