#!/usr/bin/env python3
"""Offline Supabase migration-ID parity check against a provided version list.

This tool never opens SQL contents or connects to a database. The owner must
obtain the applied IDs separately from an explicitly authorized database.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re
import sys

_VERSION_RE = re.compile(r"^[0-9]{14}$")
_FILE_RE = re.compile(r"^([0-9]{14})_[^/]+\.sql$")
_MAX_INPUT_BYTES = 128 * 1024


def compare_migrations(root: Path, applied_file: Path) -> dict[str, object]:
    """Compare immutable identifiers, not potentially misleading file counts."""
    root = Path(root).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError("root must be a directory")
    directory = root / "supabase" / "migrations"
    if (root / "supabase").is_symlink() or directory.is_symlink() or not directory.is_dir():
        raise ValueError("expected a non-symlink supabase/migrations directory")
    applied_file = Path(applied_file).expanduser()
    if applied_file.is_symlink() or not applied_file.is_file():
        raise ValueError("applied-file must be a regular non-symlink file")
    if applied_file.stat().st_size > _MAX_INPUT_BYTES:
        raise ValueError("applied-file exceeds size limit")

    observed: list[str] = []
    for entry in sorted(directory.iterdir()):
        if entry.is_symlink():
            raise ValueError("migration directory contains a symlink")
        if not entry.is_file() or not entry.name.endswith(".sql"):
            continue
        match = _FILE_RE.fullmatch(entry.name)
        if match is None:
            raise ValueError("migration SQL filename lacks a valid 14-digit version")
        observed.append(match.group(1))

    applied: list[str] = []
    with applied_file.open("r", encoding="utf-8") as stream:
        for line in stream:
            value = line.strip()
            if not value:
                continue
            if not _VERSION_RE.fullmatch(value):
                raise ValueError("applied-file must contain only 14-digit version IDs")
            applied.append(value)

    if not observed:
        raise ValueError("no Supabase SQL migration files were found")
    if not applied:
        raise ValueError("no applied migration versions were provided")

    repository_duplicates = sorted(version for version, count in Counter(observed).items() if count > 1)
    applied_duplicates = sorted(version for version, count in Counter(applied).items() if count > 1)
    repository = set(observed)
    database = set(applied)
    missing = sorted(repository - database)
    unexpected = sorted(database - repository)
    matches = not (missing or unexpected or repository_duplicates or applied_duplicates)
    return {
        "schema_version": "1.0",
        "mode": "offline_supabase_version_parity",
        "result": "match" if matches else "difference",
        "repository_versions_count": len(repository),
        "applied_versions_count": len(database),
        "pending_in_database": missing,
        "unexpected_in_database": unexpected,
        "duplicate_repository_versions": repository_duplicates,
        "duplicate_applied_versions": applied_duplicates,
        "limitations": (
            "Offline comparison of version IDs only. Does not connect to any database, "
            "verify which environment supplied applied IDs, prove SQL was executed, "
            "detect schema drift, or authorize migration application."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True, help="Authorized project directory")
    parser.add_argument("--applied-file", type=Path, required=True,
                        help="Local text file of applied 14-digit versions, one per line")
    args = parser.parse_args()
    try:
        result = compare_migrations(args.root, args.applied_file)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"Migration parity unavailable: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["result"] == "match" else 1


if __name__ == "__main__":
    raise SystemExit(main())
