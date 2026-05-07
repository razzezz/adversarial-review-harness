"""Unit tests for scout-sqli's AST-based detection primitives.

Mirrors scout-supply-chain's helper-import pattern. Tests exercise
the pure-function detector against hand-crafted fixture files.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
DETECTOR = REPO_ROOT / ".claude" / "tools" / "scout_sqli_detect.py"


def _load():
    spec = importlib.util.spec_from_file_location("scout_sqli_detect", DETECTOR)
    assert spec and spec.loader, f"cannot load {DETECTOR}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Positive: f-string, %, .format(), + concat into cursor.execute.
# ---------------------------------------------------------------------------


def test_fstring_into_execute_flags(tmp_path):
    mod = _load()
    src = tmp_path / "app.py"
    src.write_text(
        "def search(q, conn):\n"
        "    return conn.execute(f\"SELECT * FROM t WHERE n = '{q}'\")\n"
    )
    findings = mod.scan_project(tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == "CWE-89"
    assert f.severity == "high"  # not in a handler-named function
    assert "execute" in f.sink
    assert f.source_file.endswith("app.py")


def test_percent_interp_into_execute_flags(tmp_path):
    mod = _load()
    src = tmp_path / "app.py"
    src.write_text(
        "def search(q, conn):\n"
        "    return conn.execute(\"SELECT * FROM t WHERE n = '%s'\" % q)\n"
    )
    findings = mod.scan_project(tmp_path)
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-89"


def test_dotformat_into_execute_flags(tmp_path):
    mod = _load()
    src = tmp_path / "app.py"
    src.write_text(
        "def search(q, conn):\n"
        "    return conn.execute(\"SELECT * FROM t WHERE n = '{}'\".format(q))\n"
    )
    findings = mod.scan_project(tmp_path)
    assert len(findings) == 1


def test_plus_concat_into_execute_flags(tmp_path):
    mod = _load()
    src = tmp_path / "app.py"
    src.write_text(
        "def search(q, conn):\n"
        "    return conn.execute(\"SELECT * FROM t WHERE n = '\" + q + \"'\")\n"
    )
    findings = mod.scan_project(tmp_path)
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Positive: SQLAlchemy text(...) with interpolation.
# ---------------------------------------------------------------------------


def test_sqlalchemy_text_fstring_flags(tmp_path):
    mod = _load()
    src = tmp_path / "app.py"
    src.write_text(
        "from sqlalchemy import text\n"
        "def q(session, n):\n"
        "    return session.execute(text(f\"SELECT * FROM t WHERE n = '{n}'\"))\n"
    )
    findings = mod.scan_project(tmp_path)
    # Both the execute(text(...)) outer call and the text(f"...") inner call
    # could match. The detector emits for text(...) specifically.
    assert any(f.sink and "text" in f.sink for f in findings)


# ---------------------------------------------------------------------------
# Positive: Django .raw(f"...").
# ---------------------------------------------------------------------------


def test_django_raw_fstring_flags(tmp_path):
    mod = _load()
    src = tmp_path / "app.py"
    src.write_text(
        "def q(n):\n"
        "    return Model.objects.raw(f\"SELECT * FROM t WHERE n = '{n}'\")\n"
    )
    findings = mod.scan_project(tmp_path)
    assert len(findings) == 1
    assert "raw" in findings[0].sink


# ---------------------------------------------------------------------------
# Negative: parameterised queries and constants.
# ---------------------------------------------------------------------------


def test_parameterised_query_no_finding(tmp_path):
    mod = _load()
    src = tmp_path / "app.py"
    src.write_text(
        "def search(q, conn):\n"
        "    return conn.execute(\"SELECT * FROM t WHERE n = ?\", (q,))\n"
    )
    findings = mod.scan_project(tmp_path)
    assert findings == []


def test_constant_sql_no_finding(tmp_path):
    mod = _load()
    src = tmp_path / "app.py"
    src.write_text(
        "def all_items(conn):\n"
        "    return conn.execute(\"SELECT * FROM items\")\n"
    )
    findings = mod.scan_project(tmp_path)
    assert findings == []


# ---------------------------------------------------------------------------
# Handler-name heuristic: upgrades severity to critical.
# ---------------------------------------------------------------------------


def test_handler_name_upgrades_to_critical(tmp_path):
    mod = _load()
    src = tmp_path / "app.py"
    src.write_text(
        "class Handler:\n"
        "    def do_GET(self):\n"
        "        q = self.path\n"
        "        self.cursor.execute(f\"SELECT * FROM t WHERE n = '{q}'\")\n"
    )
    findings = mod.scan_project(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == "critical"


# ---------------------------------------------------------------------------
# End-to-end: toy-app _handle_search fixture (will plant in Task 4).
# ---------------------------------------------------------------------------


def test_toy_app_search_handler_pattern(tmp_path):
    """Mirror the toy-app planted pattern (Task 4). Must flag as critical."""
    mod = _load()
    src = tmp_path / "app.py"
    src.write_text(
        "class ToyHandler:\n"
        "    def _handle_search(self):\n"
        "        import sqlite3\n"
        "        q = self.path.split('q=', 1)[1] if 'q=' in self.path else ''\n"
        "        conn = sqlite3.connect(':memory:')\n"
        "        results = conn.execute(f\"SELECT * FROM items WHERE name = '{q}'\").fetchall()\n"
        "        return results\n"
    )
    findings = mod.scan_project(tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == "CWE-89"
    assert f.severity == "critical"  # _handle_search matches handler-name heuristic
    assert f.poc_applicable is True
