from __future__ import annotations

import compileall

from tests.conftest import PROJECT_ROOT


def test_project_compiles():
    assert compileall.compile_dir(str(PROJECT_ROOT / "app"), quiet=1)
    assert compileall.compile_dir(str(PROJECT_ROOT / "tests"), quiet=1)

