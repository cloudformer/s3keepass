"""Compatibility fixtures: keepassxc-cli (`kx`) and the web UI's vault code (`ours`), both in the keepassxc container.

The two sides and how a vault is read by each are in kdbx_sides.py. Without the container these tests are
skipped: python3 -m pytest tests -q --docker up | run | down starts it (compose service "keepassxc").
"""
import os
import re
import shutil

import pytest

import compat_report
from kdbx_sides import Box, KeePassXC, Ours, _exec


@pytest.fixture(scope="session")
def container():
    name = os.environ.get("KEEPASSXC_CONTAINER")
    if not name:   # set by compat_docker when the container runs: python3 -m pytest tests -q --docker up | run | down
        pytest.skip("keepassxc (the reference) is not running: python3 -m pytest tests -q --docker up | run | down")
    code, out, err = _exec(name, ["keepassxc-cli", "--version"])
    if code:
        pytest.skip(f"keepassxc-cli in {name} does not answer: {err.strip()}")
    compat_report.versions["reference"] = f"KeePassXC {out.strip()} (keepassxc-cli, Docker)"
    return name


@pytest.fixture
def box(request, container):
    b = Box(re.sub(r"\W", "_", request.node.name))
    yield b
    shutil.rmtree(b.host_dir, ignore_errors=True)


@pytest.fixture
def kx(container):
    return KeePassXC(container)


@pytest.fixture
def ours(container, box):
    return Ours(container, box)
