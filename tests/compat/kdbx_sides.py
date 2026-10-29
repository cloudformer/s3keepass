"""The two sides of the compatibility tests: s3keepass's vault files vs KeePassXC (keepassxc-cli), both in the keepassxc container.

The reference is KeePassXC's own command line (tests/compat/keepassxc/Dockerfile). The project side is the web
UI's crypto path run headless: tests/compat/kdbx_node.js loads src/server/vendor/*.js and the `vault-core`
block of src/server/index.html into Node — the same code the browser runs. Every file one side writes is read
by both, and the two readings must be equal (and equal to what was written).

    python3 -m pytest tests -q --docker up | run | down    starts the container (compose service "keepassxc")
    python3 -m pytest tests -q                             without it running, these tests are skipped

Files are handed over in tests/compat/.work/<test>/ (gitignored), mounted at /repo in the container.
"""
import json
import os
import re
import subprocess
import uuid
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WORK = os.path.join(ROOT, "tests", "compat", ".work")
STANDARD = {"Title": "title", "UserName": "username", "Password": "password", "URL": "url", "Notes": "notes"}


class Refused(Exception):
    """The vault did not open: wrong master password, or a key file is needed."""


def _exec(container, args, stdin=""):
    r = subprocess.run(["docker", "exec", "-i", container] + args, input=stdin, capture_output=True, text=True, timeout=300)
    return r.returncode, r.stdout, r.stderr


class Box:
    """A directory both sides see: the host path for Python, /repo/... in the container."""

    def __init__(self, name):
        self.host_dir = os.path.join(WORK, name)
        os.makedirs(self.host_dir, exist_ok=True)

    def host(self, f):
        return os.path.join(self.host_dir, f)

    def box(self, f):
        return "/repo/" + os.path.relpath(self.host(f), ROOT).replace(os.sep, "/")


class KeePassXC:
    """keepassxc-cli. The master password goes in on stdin, as the CLI reads it."""

    def __init__(self, container):
        self.container = container

    def cli(self, *args, stdin=""):
        code, out, err = _exec(self.container, ["keepassxc-cli"] + list(args), stdin)
        if code and not err.strip() and "-q" in args:   # -q silences the error too: ask again without it to learn why
            err = _exec(self.container, ["keepassxc-cli"] + [a for a in args if a != "-q"], stdin)[2]
        if code and re.search(r"invalid credentials|wrong key|HMAC mismatch|Error while reading the database", err, re.I):
            raise Refused(err.strip())
        assert code == 0, f"keepassxc-cli {' '.join(args)} failed ({code}): {err.strip()}"
        return out

    def create(self, f, password, key_file=None, decryption_time=None):
        args = ["db-create", "-q", "--set-password"]
        args += ["--set-key-file", key_file] if key_file else []
        args += ["-t", str(decryption_time)] if decryption_time else []
        self.cli(*args, f, stdin=f"{password}\n{password}\n")

    def mkdir(self, f, password, group, key=None):
        self.cli("mkdir", "-q", *(["-k", key] if key else []), f, group, stdin=password + "\n")

    def add(self, f, password, path, username="", url="", notes="", entry_password=""):
        self.cli("add", "-q", "-u", username, "--url", url, "--notes", notes, "-p", f, path,
                 stdin=f"{password}\n{entry_password}\n")

    def edit(self, f, password, path, *opts):
        self.cli("edit", "-q", *opts, f, path, stdin=password + "\n")

    def rm(self, f, password, path):
        self.cli("rm", "-q", f, path, stdin=password + "\n")

    def info(self, f, password):
        return self.cli("db-info", "-q", f, stdin=password + "\n")

    def add_key_file(self, f, password, key_file):
        """Add a key file to a password-only vault (KeePassXC's own db-edit)."""
        self.cli("db-edit", "-q", "--set-key-file", key_file, f, stdin=password + "\n")

    def attachment_import(self, f, password, entry, name, file):
        self.cli("attachment-import", "-q", f, entry, name, file, stdin=password + "\n")

    def attachment_export(self, f, password, entry, name):
        return self.cli("attachment-export", "-q", "--stdout", f, entry, name, stdin=password + "\n")

    def tree(self, f, password, key=None):
        """The whole vault from KeePassXC's XML export, in the shape kdbx_node.js dumps."""
        xml = self.cli("export", "-q", "-f", "xml", *(["-k", key] if key else []), f, stdin=password + "\n")
        doc = ET.fromstring(xml[xml.index("<"):])
        bin_uuid = doc.findtext("Meta/RecycleBinUUID") if doc.findtext("Meta/RecycleBinEnabled") == "True" else None
        found = {}

        def entry(e):
            out = {"title": "", "username": "", "password": "", "url": "", "notes": "", "custom": []}
            for s in e.findall("String"):
                key, value = s.findtext("Key"), s.find("Value")
                text = (value.text or "") if value is not None else ""
                if key in STANDARD:
                    out[STANDARD[key]] = text
                else:
                    out["custom"].append({"name": key, "value": text,
                                          "protected": value is not None and value.get("ProtectInMemory") == "True"})
            out["tags"] = [t.strip() for t in re.split(r"[;,]", e.findtext("Tags") or "") if t.strip()]
            out["history"] = len(e.findall("History/Entry"))
            return out

        def walk(g):
            groups = []
            for c in g.findall("Group"):
                if bin_uuid and c.findtext("UUID") == bin_uuid:
                    found["bin"] = walk(c)
                else:
                    groups.append(walk(c))
            return {"name": g.findtext("Name") or "", "groups": groups, "entries": [entry(e) for e in g.findall("Entry")]}

        tree = walk(doc.find("Root/Group"))
        tree["recycleBin"] = found.get("bin")
        return norm(tree)


class Ours:
    """The web UI's vault code (index.html vault-core + vendored kdbxweb/argon2), run by kdbx_node.js."""

    def __init__(self, container, box):
        self.container, self.box = container, box

    def node(self, *args):
        code, out, err = _exec(self.container, ["node", "/repo/tests/compat/kdbx_node.js"] + list(args))
        if code == 2:
            raise Refused(out.strip())
        assert code == 0, f"kdbx_node.js {args[0]} failed ({code}): {err.strip()[-1500:]}"
        return json.loads(out)

    def _json(self, data):
        name = f"{uuid.uuid4().hex[:8]}.json"
        with open(self.box.host(name), "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False)
        return self.box.box(name)

    def create(self, f, password, tree, key=None):
        self.node("create", f, password, self._json(tree), *(["--key", key] if key else []))

    def tree(self, f, password, key=None):
        return norm(self.node("dump", f, password, *(["--key", key] if key else [])))

    def new_key_file(self, f):
        self.node("keyfile", f)

    def edit(self, f, password, ops, out, key=None):
        self.node("edit", f, password, self._json(ops), out, *(["--key", key] if key else []))

    def info(self, f, password):
        return self.node("info", f, password)


def norm(tree):
    """Order-independent: groups by name, entries by title, custom attributes by name; the recycle bin apart."""
    def entry(e):
        return {"title": e["title"], "username": e["username"], "password": e["password"], "url": e["url"],
                "notes": e["notes"].replace("\r\n", "\n"), "tags": sorted(e.get("tags", [])),
                "custom": sorted(({"name": c["name"], "value": c["value"], "protected": bool(c["protected"])}
                                  for c in e.get("custom", [])), key=lambda c: c["name"]),
                "history": e.get("history", 0)}

    def group(g):
        return {"name": g.get("name", ""), "groups": sorted((group(x) for x in g.get("groups", [])), key=lambda x: x["name"]),
                "entries": sorted((entry(x) for x in g.get("entries", [])), key=lambda x: x["title"])}

    out = group(tree)
    out["recycleBin"] = group(tree["recycleBin"]) if tree.get("recycleBin") else None
    return out


def expected(tree, name, recycle=None):
    """The normalised reading of `tree` (kdbx_node.js create's input), with the root group called `name`."""
    def fill(g):
        return {"name": g.get("name", ""), "groups": [fill(x) for x in g.get("groups", [])],
                "entries": [dict({"username": "", "password": "", "url": "", "notes": "", "tags": [], "custom": [],
                                  "history": 0}, **e) for e in g.get("entries", [])]}
    out = fill(dict(tree, name=name))
    out["recycleBin"] = fill(recycle) if recycle else None
    return norm(out)
