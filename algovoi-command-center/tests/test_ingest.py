"""Unit tests for the Import / Ingest / Watcher console module.

These exercise the pure logic and rendering that do not need the importer add-on installed (that end to
end path is validated on VM2). They confirm: the nav exposes the Import tab, the page renders in the
add-on-absent and archive-absent branches, landing-zone enumeration works, and the writer guards reject
bad input without touching a background thread.
"""
import os
import tempfile

from algovoi_command_center import ingest, theme


def test_nav_has_import_tab():
    keys = {k for _href, _label, k in theme._NAV}
    assert "ingest" in keys
    labels = {label for _href, label, _k in theme._NAV}
    assert "Import" in labels


def test_render_when_addon_absent_or_archive_absent():
    user = {"username": "op", "role": "admin"}
    # add-on may or may not be installed in this env; both branches must render a themed page.
    html_out = ingest.render_ingest_page(False, user=user, can_manage=True)
    assert "Import" in html_out and "<html" in html_out
    if not ingest.available():
        assert "not installed" in html_out


def test_landing_zones_lists_subdirs_with_counts():
    d = tempfile.mkdtemp()
    os.makedirs(os.path.join(d, "acme"))
    open(os.path.join(d, "acme", "a.bin"), "wb").write(b"x")
    open(os.path.join(d, "acme", "b.bin"), "wb").write(b"y")
    os.environ["COMMAND_CENTER_INGEST_DIR"] = d
    try:
        zones = {z["name"]: z for z in ingest.landing_zones()}
        assert "(root)" in zones and "acme" in zones
        assert zones["acme"]["files"] == 2
        assert zones["(root)"]["files"] == 2
    finally:
        del os.environ["COMMAND_CENTER_INGEST_DIR"]


def test_start_import_rejects_bad_input_without_thread():
    # No archive is touched: a non-directory path is rejected up front, so nothing is scheduled.
    job_id, msg = ingest.start_import(object(), "/no/such/dir/xyz", strategy="merkle", mode="bridge")
    assert job_id is None and "not a server directory" in msg
    job_id, msg = ingest.start_import(object(), "/tmp", strategy="nope", mode="bridge")
    assert job_id is None and "invalid strategy" in msg
    assert ingest.active_job() is None
    assert ingest.watcher_running() is False


def test_watch_rejects_bad_path():
    ok, msg = ingest.start_watch(object(), "/no/such/dir/xyz")
    assert ok is False and "not a server directory" in msg
    assert ingest.watcher_running() is False
