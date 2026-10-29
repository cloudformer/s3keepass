"""Test setup: src/server and client/ on the import path, an in-memory fake S3, the compatibility-report hooks.

The fake S3 implements what lambda_function uses on a versioned bucket: ETag, conditional PUT (If-Match /
If-None-Match), HEAD 404, delete markers, object versions and both list paginators. The report hooks must
live in the ROOT conftest so they see the whole run (regression + compat).
"""
import datetime
import hashlib
import io
import os
import re
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src", "server"))
sys.path.insert(0, os.path.join(ROOT, "client"))

# the pip / import name, read from client/pyproject.toml so nothing else hard-codes it
with open(os.path.join(ROOT, "client", "pyproject.toml"), encoding="utf-8") as _f:
    PACKAGE = re.search(r'^name\s*=\s*"([^"]+)"', _f.read(), re.M).group(1)
os.environ["PACKAGE"] = PACKAGE

# lambda_function reads these at import time
os.environ.setdefault("USER_NAME", "admin")
os.environ.setdefault("PASSWORD", "pw")
os.environ.setdefault("BUCKET", "test-bucket")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-2")

from botocore.exceptions import ClientError  # noqa: E402

from compat_report import (pytest_collection_modifyitems, pytest_configure,  # noqa: E402,F401
                           pytest_runtest_logreport, pytest_sessionfinish, pytest_terminal_summary)


pytest_plugins = ["compat_docker", "compat_aws"]   # python3 -m pytest tests -q [--docker up | run | down] [--aws <var-file>]


class FakeS3:
    """A versioned bucket in memory. self.calls records every put_object's keyword arguments."""

    def __init__(self):
        self.versions = {}   # key -> [{"id", "body", "etag", "modified", "deleted"}], oldest first
        self.calls = []
        self.clock = datetime.datetime(2026, 10, 29, tzinfo=datetime.timezone.utc)

    def _tick(self):
        self.clock += datetime.timedelta(seconds=1)
        return self.clock

    @staticmethod
    def _err(code, op):
        raise ClientError({"Error": {"Code": code, "Message": code}}, op)

    def _current(self, key):
        v = (self.versions.get(key) or [None])[-1]
        return v if v and not v["deleted"] else None

    def _add(self, key, **v):
        vs = self.versions.setdefault(key, [])
        vs.append(dict(v, id=f"v{len(vs) + 1}-{key}", modified=self._tick()))
        return vs[-1]

    def put_object(self, Bucket, Key, Body, IfMatch=None, IfNoneMatch=None, **kwargs):
        self.calls.append(dict(kwargs, Key=Key, IfMatch=IfMatch, IfNoneMatch=IfNoneMatch))
        cur = self._current(Key)
        if IfNoneMatch == "*" and cur:
            self._err("PreconditionFailed", "PutObject")
        if IfMatch is not None and not cur:
            self._err("NoSuchKey", "PutObject")
        if IfMatch is not None and cur["etag"] != IfMatch:
            self._err("PreconditionFailed", "PutObject")
        body = bytes(Body)
        v = self._add(Key, body=body, etag='"%s"' % hashlib.md5(body + Key.encode()).hexdigest(), deleted=False)
        return {"ETag": v["etag"], "VersionId": v["id"]}

    def get_object(self, Bucket, Key, VersionId=None):
        v = next((x for x in self.versions.get(Key, []) if x["id"] == VersionId), None) if VersionId else self._current(Key)
        if not v or v["deleted"]:
            self._err("NoSuchVersion" if VersionId else "NoSuchKey", "GetObject")
        return {"ETag": v["etag"], "VersionId": v["id"], "Body": io.BytesIO(v["body"])}

    def head_object(self, Bucket, Key):
        cur = self._current(Key)
        if not cur:
            self._err("404", "HeadObject")
        return {"ETag": cur["etag"]}

    def delete_object(self, Bucket, Key):
        self._add(Key, body=b"", etag="", deleted=True)
        return {"DeleteMarker": True}

    def get_paginator(self, name):
        s3 = self

        class Paginator:
            def paginate(self, Bucket, Prefix):
                keys = sorted(k for k in s3.versions if k.startswith(Prefix))
                if name == "list_objects_v2":
                    yield {"Contents": [{"Key": k, "Size": len(c["body"]), "ETag": c["etag"], "LastModified": c["modified"]}
                                        for k in keys for c in [s3._current(k)] if c]}
                else:
                    page = {"Versions": [], "DeleteMarkers": []}
                    for k in keys:
                        for i, v in enumerate(s3.versions[k]):
                            row = {"Key": k, "VersionId": v["id"], "LastModified": v["modified"],
                                   "IsLatest": i == len(s3.versions[k]) - 1}
                            if v["deleted"]:
                                page["DeleteMarkers"].append(row)
                            else:
                                page["Versions"].append(dict(row, Size=len(v["body"]), ETag=v["etag"]))
                    yield page
        return Paginator()


@pytest.fixture
def fake_s3(monkeypatch):
    import lambda_function
    fake = FakeS3()
    monkeypatch.setattr(lambda_function, "s3", fake)
    return fake
