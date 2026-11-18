# Third-Party Notices — `algovoi-archive-auditor`

This AlgoVoi product is proprietary (`LicenseRef-AlgoVoi-Commercial-1.0` / `LicenseRef-AlgoVoi-Internal`). It **depends on**, but does **not** copy, modify, or vendor, the open-source libraries listed below. Each is installed from PyPI under its own licence; its full licence text ships inside that library's own distribution.

All listed dependencies use **permissive** licences (MIT / BSD / Apache-2.0). None are copyleft. No third-party source is bundled into this package.

> **If this package is ever redistributed in a *bundled* form** (Docker image, offline / air-gapped installer, PyInstaller/frozen build) the full licence + NOTICE text of every dependency in the frozen tree **must be reproduced here**. Generate that at bundle time with e.g. `pip-licenses --format=plain-vertical --with-license-file` over the pinned environment. The list below covers the **direct** dependencies; those carry their own transitive dependencies under their respective licences.

## Direct dependencies

| Library | Declared version | Licence (SPDX) | Source | Used for |
|---|---|---|---|---|
| `fastapi` | `>=0.110` | MIT | <https://github.com/fastapi/fastapi> | ASGI web framework (service mode) |
| `pydantic` | `>=2.5` | MIT | <https://github.com/pydantic/pydantic> | data models / schema validation |
| `uvicorn` _(optional: `serve`)_ | `>=0.29` | BSD-3-Clause | <https://github.com/encode/uvicorn> | ASGI server (service mode) |

_AlgoVoi — chopmob@gmail.com_
