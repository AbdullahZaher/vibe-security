"""Offline artifact validation primitives. Consistency checks are not attestations."""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import selectors
import time
import subprocess

ASSETS = Path(__file__).resolve().parents[1] / "assets"
MAX_BYTES = 2_000_000


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_index(rows, key="id"):
    result = {}
    for row in rows:
        value = row.get(key)
        require(isinstance(value, str) and value.strip(), f"missing {key}")
        require(value not in result, f"duplicate {key}: {value}")
        result[value] = row
    return result


def safe_relative_path(value):
    require(isinstance(value, str) and value and not any(ord(c) < 32 for c in value), "invalid path")
    path = PurePosixPath(value)
    require(not path.is_absolute() and "\\" not in value and ":" not in value,
            "path must be relative POSIX path")
    require(all(p not in {"", ".", "..", ".git"} for p in value.split("/")), "unsafe path component")
    return path


def trusted_root(root):
    """Canonicalize an operator-supplied root and reject mutable symlink components.

    Frozen roots may sit below immutable system links (for example macOS
    ``/var`` -> ``/private/var``). Only root-owned links inside directories that
    the current user cannot modify are followed. A link created by the user or
    inside a writable directory remains rejected, so untrusted repository or
    task data cannot redirect the artifact boundary. Relative components below
    the resolved root are still walked with O_NOFOLLOW and are never followed.
    """
    original = Path(root).absolute()
    require(".." not in original.parts, "unsafe artifact root")
    current = Path(original.anchor)
    for part in original.parts[1:]:
        candidate = current / part
        if candidate.is_symlink():
            parent = current.stat()
            link = candidate.lstat()
            immutable_parent = parent.st_uid == 0 and (parent.st_mode & 0o022) == 0
            require(link.st_uid == 0 and immutable_parent,
                    "artifact root contains a mutable symlink component")
        current = candidate
    resolved = Path(os.path.realpath(original))
    require(".." not in resolved.parts and resolved.is_dir(),
            "artifact root is not a directory")
    return resolved


def read_artifact(root, relative_path, max_bytes=MAX_BYTES):
    """Open a regular file through no-follow directory descriptors; never follow links.

    Fail closed on platforms lacking these OS primitives. Callers may still use
    source-only validation without retained artifact files on such platforms.
    """
    parts = safe_relative_path(relative_path).parts
    require(hasattr(os, "O_NOFOLLOW") and os.open in os.supports_dir_fd,
            "safe artifact reading unavailable on this host")
    root = trusted_root(root)
    # Walk the resolved root through descriptors too: an lstat-then-open
    # ancestor check would leave a symlink replacement race.
    fd = os.open(root.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in root.parts[1:] + parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        leaf = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            meta = os.fstat(leaf)
            require(stat.S_ISREG(meta.st_mode), "artifact is not a regular file")
            require(meta.st_size <= max_bytes, "artifact too large")
            with os.fdopen(leaf, "rb", closefd=False) as stream:
                content = stream.read(max_bytes + 1)
            require(len(content) <= max_bytes, "artifact too large")
            return content
        finally:
            os.close(leaf)
    finally:
        os.close(fd)


def write_new_artifact(path, content):
    """Create a private regular artifact without overwrites or symlink traversal."""
    path = Path(path).absolute()
    require(".." not in path.parts and path.name not in {"", ".", ".."}, "unsafe output path")
    require(hasattr(os, "O_NOFOLLOW") and os.open in os.supports_dir_fd,
            "safe artifact writing unavailable on this host")
    ancestor, missing = path.parent, [path.name]
    while not ancestor.exists():
        if ancestor == ancestor.parent:
            break
        missing.append(ancestor.name)
        ancestor = ancestor.parent
    target = trusted_root(ancestor).joinpath(*reversed(missing))
    fd = os.open(target.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in target.parts[1:-1]:
            try:
                os.mkdir(part, mode=0o700, dir_fd=fd)
            except FileExistsError:
                pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        leaf = os.open(target.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                       0o600, dir_fd=fd)
        with os.fdopen(leaf, "w", encoding="utf-8") as stream:
            stream.write(content)
    finally:
        os.close(fd)


def load_json(path):
    path = Path(path).absolute()
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, f"duplicate JSON key: {key}")
            result[key] = value
        return result
    def invalid(value):
        raise ValueError(f"invalid JSON number: {value}")
    raw = read_artifact(path.parent, path.name)
    try:
        decoded = raw.decode("utf-8")
    except UnicodeError as exc:
        raise ValueError("artifact JSON must be UTF-8") from exc
    # Bound nesting before decoding; JSON parser recursion limits vary by host.
    depth, quoted, escaped = 0, False, False
    for char in raw:
        if quoted:
            if escaped:
                escaped = False
            elif char == 92:
                escaped = True
            elif char == 34:
                quoted = False
        elif char == 34:
            quoted = True
        elif char in (91, 123):
            depth += 1
            require(depth <= 128, "excessively nested JSON")
        elif char in (93, 125):
            depth -= 1
    try:
        return json.loads(decoded, object_pairs_hook=pairs, parse_constant=invalid)
    except (RecursionError, UnicodeError) as exc:
        raise ValueError("invalid or excessively nested JSON") from exc


def validate_schema(data, schema_name):
    """Validate the deliberately small JSON Schema vocabulary used by these assets.

    Unknown validation keywords fail closed so adding a schema constraint cannot
    silently weaken this dependency-free validator. No remote references resolve.
    """
    require(Path(schema_name).name == schema_name, "schema name must be an asset basename")
    schema = load_json(ASSETS / schema_name)
    supported = {"$schema", "$id", "$defs", "title", "description", "default", "examples",
                 "$ref", "type", "required", "properties", "additionalProperties", "items",
                 "minItems", "maxItems", "uniqueItems", "minLength", "maxLength", "pattern",
                 "enum", "const", "minimum", "maximum", "allOf", "anyOf", "oneOf"}
    types = {"object": lambda x: isinstance(x, dict), "array": lambda x: isinstance(x, list),
             "string": lambda x: isinstance(x, str), "boolean": lambda x: type(x) is bool,
             "integer": lambda x: type(x) is int, "number": lambda x: type(x) in {int, float},
             "null": lambda x: x is None}
    def check(value, rule, location):
        if isinstance(rule, bool):
            require(rule, f"{location}: forbidden value")
            return
        require(not set(rule) - supported, f"unsupported schema keywords: {set(rule) - supported}")
        if "$ref" in rule:
            ref = rule["$ref"]
            require(ref.startswith("#/"), "only local schema references are supported")
            target = schema
            for token in ref[2:].split("/"):
                target = target[token.replace("~1", "/").replace("~0", "~")]
            check(value, target, location)
        for mode in ("allOf", "anyOf", "oneOf"):
            if mode in rule:
                matches = 0
                for candidate in rule[mode]:
                    try:
                        check(value, candidate, location)
                        matches += 1
                    except ValueError:
                        pass
                require(matches == len(rule[mode]) if mode == "allOf" else
                        matches == 1 if mode == "oneOf" else matches > 0,
                        f"{location}: {mode} failed")
        if "type" in rule:
            names = rule["type"] if isinstance(rule["type"], list) else [rule["type"]]
            require(all(n in types for n in names), "unknown schema type")
            require(any(types[n](value) for n in names), f"{location}: wrong type")
        if "enum" in rule:
            require(any(type(value) is type(v) and value == v for v in rule["enum"]), f"{location}: invalid enum")
        if "const" in rule:
            require(type(value) is type(rule["const"]) and value == rule["const"], f"{location}: invalid const")
        if isinstance(value, dict):
            require(set(rule.get("required", [])) <= value.keys(), f"{location}: missing required properties")
            props = rule.get("properties", {})
            for key, child in value.items():
                if key in props:
                    check(child, props[key], f"{location}.{key}")
                elif rule.get("additionalProperties") is False:
                    raise ValueError(f"{location}: unexpected property {key}")
                elif isinstance(rule.get("additionalProperties"), dict):
                    check(child, rule["additionalProperties"], f"{location}.{key}")
        if isinstance(value, list):
            require(len(value) >= rule.get("minItems", 0), f"{location}: too few items")
            require(len(value) <= rule.get("maxItems", 100000), f"{location}: too many items")
            if rule.get("uniqueItems"):
                require(len({json.dumps(x, sort_keys=True) for x in value}) == len(value), f"{location}: duplicate items")
            for i, child in enumerate(value):
                if "items" in rule:
                    check(child, rule["items"], f"{location}[{i}]")
        if isinstance(value, str):
            require(len(value) >= rule.get("minLength", 0), f"{location}: too short")
            require(len(value) <= rule.get("maxLength", MAX_BYTES), f"{location}: too long")
            if "pattern" in rule:
                require(re.search(rule["pattern"], value) is not None, f"{location}: invalid pattern")
        if type(value) in {int, float}:
            require(not isinstance(value, float) or math.isfinite(value), f"{location}: nonfinite number")
            require(value >= rule.get("minimum", float("-inf")) and value <= rule.get("maximum", float("inf")),
                    f"{location}: number outside bounds")
    check(data, schema, "$")


def stable_id(prefix, *identity):
    body = json.dumps(identity, ensure_ascii=True, separators=(",", ":"))
    return prefix + hashlib.sha256(body.encode()).hexdigest()[:24]


def bounded_command(command, env, max_bytes=2_000_000, timeout=30):
    """Drain metadata incrementally; target metadata cannot allocate unbounded output."""
    deadline = time.monotonic() + timeout
    chunks = bytearray()
    with subprocess.Popen(command, env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL) as process:
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        raise ValueError("Git metadata read timed out")
                    part = os.read(process.stdout.fileno(), min(65536, max_bytes + 1 - len(chunks)))
                    if not part:
                        break
                    chunks.extend(part)
                    if len(chunks) > max_bytes:
                        raise ValueError("Git metadata exceeds limit; narrow the reviewed scope")
            code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
        except BaseException:
            process.kill()
            process.wait()
            raise
    return subprocess.CompletedProcess(command, code, bytes(chunks), b"")


def frozen_source(root, revision, path):
    """Read a bounded regular blob from an exact Git commit, never the worktree."""
    safe_relative_path(path)
    require(re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", revision) is not None, "full immutable Git revision required")
    # Never read blobs borrowed through an alternate object store, and never
    # honor GIT_ALTERNATE_OBJECT_DIRECTORIES: both let a target make the audit
    # read source from another repository.
    gitdir = Path(root).resolve() / ".git"
    alternates = gitdir / "objects" / "info" / "alternates"
    if alternates.exists():
        raise ValueError("git alternate object stores are not allowed")
    if "GIT_ALTERNATE_OBJECT_DIRECTORIES" in os.environ:
        raise ValueError("GIT_ALTERNATE_OBJECT_DIRECTORIES is not allowed")
    # Do not inherit Git config/environment injection or invoke hooks, filters,
    # textconv, pagers, network transports or target-controlled executables.
    env = {"PATH": os.defpath, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_NO_REPLACE_OBJECTS": "1", "GIT_TERMINAL_PROMPT": "0", "GIT_NO_LAZY_FETCH": "1"}
    command = ["git", "--no-replace-objects", "--literal-pathspecs", "-c", "protocol.allow=never",
               "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.devnull,
               "-C", str(Path(root).absolute())]
    def git(*args):
        run = bounded_command(command + list(args), env, max_bytes=MAX_BYTES, timeout=15)
        require(run.returncode == 0, "frozen source Git read failed")
        return run.stdout
    require(git("cat-file", "-t", revision).strip() == b"commit", "revision must name a commit")
    entry = git("ls-tree", "-z", revision, "--", path)
    rows = [x for x in entry.split(b"\0") if x]
    require(len(rows) == 1, "source path does not exist at revision")
    meta, actual_path = rows[0].split(b"\t", 1)
    mode, kind, oid = meta.split()
    require(actual_path.decode("utf-8") == path and mode in {b"100644", b"100755"} and kind == b"blob",
            "source must be a regular frozen file, not symlink/submodule/directory")
    require(int(git("cat-file", "-s", oid.decode()).strip()) <= MAX_BYTES, "source too large")
    body = git("cat-file", "blob", oid.decode())
    require(len(body) <= MAX_BYTES, "source too large")
    return body


def validate_source(source, revision, source_root=None):
    require(isinstance(source, dict), "source must be an object")
    require(set(source) == {"path", "line_start", "line_end", "revision", "status", "sha256"}, "invalid source fields")
    safe_relative_path(source["path"])
    require(isinstance(revision, str) and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", revision) is not None,
            "immutable source revision required even for unverified sources")
    require(source["revision"] == revision, "source revision mismatch")
    require(type(source["line_start"]) is int and type(source["line_end"]) is int and
            1 <= source["line_start"] <= source["line_end"], "invalid source lines")
    require(source["status"] in {"verified", "not_verified"}, "invalid source status")
    if source["status"] == "not_verified":
        require(source["sha256"] == "" or re.fullmatch(r"[0-9a-f]{64}", source["sha256"]), "invalid source hash")
        return False
    require(source_root is not None, "verified source requires a frozen source root")
    body = frozen_source(source_root, revision, source["path"])
    require(hashlib.sha256(body).hexdigest() == source["sha256"], "source hash mismatch")
    require(source["line_end"] <= len(body.splitlines()), "source line does not exist")
    return True
