"""Command-center UI structure tests (presentation only)."""

from __future__ import annotations

from pathlib import Path

from app.dashboard.nav import (
    AUTO_REFRESH_PAGES,
    NAV_FIREWALL,
    NAV_OVERVIEW,
    NAV_PAGES,
    NAV_SYSTEM,
)
from app.dashboard.components import render_sidebar_filters
from app.dashboard.streamlit_app import main


def test_navigation_pages_and_imports() -> None:
    assert callable(main)
    assert callable(render_sidebar_filters)
    assert NAV_OVERVIEW in NAV_PAGES
    assert NAV_FIREWALL in NAV_PAGES
    assert NAV_SYSTEM in NAV_PAGES
    assert NAV_OVERVIEW in AUTO_REFRESH_PAGES
    assert NAV_FIREWALL not in AUTO_REFRESH_PAGES


def test_data_filter_is_not_capture_mode() -> None:
    src = Path("app/dashboard/components/__init__.py").read_text(encoding="utf-8")
    app_src = Path("app/dashboard/streamlit_app.py").read_text(encoding="utf-8")
    blob = (src + "\n" + app_src).lower()
    assert '"data filter"' in blob
    assert "do not change ids capture mode" in blob
    assert "capture mode (runtime)" in blob
    assert 'selectbox("mode"' not in src.replace(" ", "").lower()


def test_firewall_and_demo_remain_outside_refresh_body() -> None:
    app_src = Path("app/dashboard/streamlit_app.py").read_text(encoding="utf-8")
    body = app_src[app_src.find("def _render_body") : app_src.find("refresh_seconds = int")]
    assert "render_firewall_panel" not in body
    assert "render_safe_demonstration" not in body
    assert "render_run_security_demo" not in body
    assert "render_security_overview" in body
    assert "render_firewall_panel" in app_src
    assert "render_safe_demonstration" in app_src
    assert "render_run_security_demo" in app_src
    assert "RUN SECURITY DEMO" in Path("app/dashboard/components/intelligence.py").read_text(
        encoding="utf-8"
    )
