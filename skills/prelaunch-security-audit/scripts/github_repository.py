#!/usr/bin/env python3
"""Optional read-only GitHub API metadata for a single explicitly allowed repo.

Set SECURITY_AUDIT_GITHUB_REPO to owner/repo, and optionally GITHUB_TOKEN to
access a private repository. No writes; no repository contents; no credentials
in output. Requires outbound network access to api.github.com.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import urllib.error
import urllib.request
from typing import Any

_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("GitHub API redirect blocked to avoid credential forwarding")


def read_repo_metadata(repo: str, *, allowed_repo: str, token: str = "") -> dict[str, Any]:
    if not allowed_repo or not _REPO_RE.fullmatch(allowed_repo):
        raise ValueError("SECURITY_AUDIT_GITHUB_REPO must be set to owner/repo")
    if repo != allowed_repo:
        raise PermissionError("Repository is not the one explicitly allowlisted")
    req = urllib.request.Request(
        f"https://api.github.com/repos/{repo}",
        method="GET",
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "prelaunch-security-audit/0.1",
            "X-GitHub-Api-Version": "2026-03-10",
            **({"Authorization": f"Bearer {token}"} if token else {}),
        },
    )
    try:
        with urllib.request.build_opener(NoRedirect()).open(req, timeout=10) as resp:
            if resp.status != 200:
                raise RuntimeError("Unexpected GitHub response status")
            payload = resp.read(100000)
        data = json.loads(payload)
    except (urllib.error.HTTPError, urllib.error.URLError) as exc:
        # Do not surface request headers, tokens or provider response bodies.
        if isinstance(exc, urllib.error.HTTPError):
            raise RuntimeError(f"GitHub API request failed (HTTP {exc.code})") from None
        raise RuntimeError("GitHub API request failed (network unavailable)") from None
    return {
        "full_name": data.get("full_name", ""),
        "private": bool(data.get("private")),
        "default_branch": data.get("default_branch", ""),
        "archived": bool(data.get("archived")),
        "disabled": bool(data.get("disabled")),
        "note": "Read-only GitHub metadata; not evidence of secure code or branch protections.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="Repo owner/name (must equal allowlist)")
    args = parser.parse_args()
    try:
        data = read_repo_metadata(
            args.repo,
            allowed_repo=os.environ.get("SECURITY_AUDIT_GITHUB_REPO", ""),
            token=os.environ.get("GITHUB_TOKEN", ""),
        )
    except (PermissionError, ValueError, RuntimeError) as exc:
        parser.error(str(exc))
    print(json.dumps(data, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
