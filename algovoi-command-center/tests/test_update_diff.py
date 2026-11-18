"""The update diff must detect installed packages that are not prefixed 'algovoi' (e.g. the substrate2
core), so an up-to-date core is not shown as '(not installed)' and offered as a spurious upgrade."""
from __future__ import annotations

from importlib import metadata

import algovoi_command_center.updates as u


def test_diff_detects_non_algovoi_installed_package():
    fv = metadata.version("fastapi")   # a non-algovoi dependency that is definitely installed
    # same version present -> not offered as an upgrade
    same = u._diff({"wheels": [{"name": f"fastapi-{fv}-py3-none-any.whl"}]})
    assert not any(x["package"] == "fastapi" for x in same)
    # a higher version -> offered, and 'from' is the real installed version, not None/"not installed"
    up = u._diff({"wheels": [{"name": "fastapi-999.0.0-py3-none-any.whl"}]})
    row = [x for x in up if x["package"] == "fastapi"][0]
    assert row["from"] == fv and row["to"] == "999.0.0"


def test_installed_version_handles_missing():
    assert u._installed_version("definitely-not-a-real-package-xyz") is None
