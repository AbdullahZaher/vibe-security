#!/usr/bin/env python3
"""Optional local-only MCP v2 adapter: bounded read-only file inventory.

Do not publish over a network or configure it against a repository you are
not authorized to access. Host-controlled MCP permissions remain in effect.
"""
from __future__ import annotations

import os
from pathlib import Path
import sys

from mcp.server import MCPServer

SKILL_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SKILL_ROOT / "scripts"))
from preflight import inventory  # noqa: E402
from github_repository import read_repo_metadata  # noqa: E402

mcp = MCPServer("Prelaunch Security Audit (Read Only)")


@mcp.tool()
def security_preflight() -> dict:
    """Inventory filenames/metadata in a fixed authorized local repo root.

    No code content, secret values, network calls or Git history are read.
    The configured root is fixed at process startup by the owner's environment.
    This tool never modifies the repository and never certifies security.
    """
    root_value = os.environ.get("SECURITY_AUDIT_REPO_ROOT", "")
    root = Path(root_value)
    if not root_value or not root.is_absolute():
        raise ValueError("SECURITY_AUDIT_REPO_ROOT must be an authorized absolute path")
    return inventory(root, max_files=20000)


@mcp.tool()
def github_repository_metadata() -> dict:
    """Get read-only metadata for one GitHub repository allowlisted by the owner.

    Requires SECURITY_AUDIT_GITHUB_REPO=owner/repo and optional GITHUB_TOKEN
    configured in the host environment. Never changes GitHub state.
    """
    repo = os.environ.get("SECURITY_AUDIT_GITHUB_REPO", "")
    return read_repo_metadata(
        repo,
        allowed_repo=repo,
        token=os.environ.get("GITHUB_TOKEN", ""),
    )


if __name__ == "__main__":
    mcp.run(transport="stdio")
