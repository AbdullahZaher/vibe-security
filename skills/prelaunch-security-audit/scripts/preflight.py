#!/usr/bin/env python3
"""Bounded, offline, filename-only inventory of an owner-authorized project.

No file contents are opened, no commands are executed, no network is used, and
symbolic links are never followed. This is not a vulnerability scanner.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from typing import Any

SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__",
    ".next", ".nuxt", ".turbo", "dist", "build", "coverage", ".cache",
    "vendor", "target", ".pytest_cache", ".mypy_cache", ".gradle",
})
MANIFESTS = frozenset({
    "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
    "bun.lockb", "bun.lock", "pyproject.toml", "requirements.txt",
    "poetry.lock", "Pipfile", "Pipfile.lock", "Cargo.toml", "Cargo.lock",
    "go.mod", "go.sum", "composer.json", "composer.lock", "Gemfile",
    "Gemfile.lock", "Dockerfile", "docker-compose.yml", "compose.yaml",
    "next.config.js", "next.config.mjs", "next.config.ts", "vite.config.ts",
    "vite.config.js", "manage.py", "supabase/config.toml",
})
ENV_NAME_RE = re.compile(r"^\.env(?:\..+)?$", re.IGNORECASE)
SENSITIVE_SUFFIXES = (".sql", ".sql.gz", ".pem", ".p12", ".pfx", ".key", ".bak")
SENSITIVE_NAMES = {"id_rsa", "id_ed25519", "credentials.json", "service-account.json"}


def inventory(root: Path, max_files: int = 20000) -> dict[str, Any]:
    """Return metadata only; never open application files or follow symlinks."""
    if max_files < 1 or max_files > 100000:
        raise ValueError("max_files must be between 1 and 100000")
    root = Path(root).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError("root must be a directory")
    seen = 0
    skipped_symlinks = 0
    manifest_paths: list[str] = []
    sensitive_filename_paths: list[str] = []
    extension_counts: Counter[str] = Counter()
    truncated = False

    for directory, dirs, filenames in os.walk(root, topdown=True, followlinks=False):
        directory_path = Path(directory)
        kept_dirs = []
        for name in sorted(dirs):
            path = directory_path / name
            if path.is_symlink():
                skipped_symlinks += 1
            elif name not in SKIP_DIRS:
                kept_dirs.append(name)
        dirs[:] = kept_dirs
        for name in sorted(filenames):
            path = directory_path / name
            if path.is_symlink():
                skipped_symlinks += 1
                continue
            if not path.is_file():
                continue
            if seen >= max_files:
                truncated = True
                dirs.clear()
                break
            seen += 1
            relative = path.relative_to(root).as_posix()
            extension_counts[path.suffix.lower() or "[none]"] += 1
            if name in MANIFESTS or relative in MANIFESTS:
                manifest_paths.append(relative)
            lower_name = name.lower()
            if (ENV_NAME_RE.fullmatch(name) or lower_name in SENSITIVE_NAMES
                    or lower_name.endswith(SENSITIVE_SUFFIXES)):
                sensitive_filename_paths.append(relative)
        if truncated:
            break

    return {
        "schema_version": "1.0",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "root": str(root),
        "files_observed": seen,
        "max_files": max_files,
        "truncated": truncated,
        "symlinks_skipped": skipped_symlinks,
        "manifests": manifest_paths[:200],
        "possible_sensitive_filenames": sensitive_filename_paths[:200],
        "extension_counts": dict(sorted(extension_counts.items())),
        "limitations": (
            "Filename/metadata inventory only; no file contents, Git history, HTTP, "
            "dependency advisories, auth behavior, or secrets were inspected. "
            "A filename alone does not prove a vulnerability or public exposure. "
            "Excluded directories and truncated results limit coverage."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path, help="Authorized local repository root")
    parser.add_argument("--out", type=Path, help="Optional JSON output file")
    parser.add_argument("--max-files", type=int, default=20000)
    args = parser.parse_args()
    try:
        data = inventory(args.root, args.max_files)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    payload = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    if args.out:
        output = args.out.expanduser()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(payload, encoding="utf-8")
        print(f"Wrote filename-only inventory: {output}")
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
