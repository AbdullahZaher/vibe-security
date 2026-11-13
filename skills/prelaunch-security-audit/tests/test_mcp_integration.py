"""Real MCP v2 stdio interoperability test, run only when SDK is installed."""
import asyncio
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

ROOT = Path(__file__).resolve().parents[1]

try:
    from mcp import Client
    from mcp.client.stdio import StdioServerParameters
except ImportError:
    Client = None
    StdioServerParameters = None


@unittest.skipIf(Client is None, "Install audited MCP Python SDK v2 to run interoperability test")
class TestMCPInterop(unittest.TestCase):
    def test_read_only_preflight_via_stdio(self):
        async def probe():
            with TemporaryDirectory() as folder:
                root = Path(folder)
                (root / "package.json").write_text('{"name":"fixture"}', encoding="utf-8")
                (root / ".env.local").write_text("TOKEN=DO_NOT_PRINT_SENTINEL", encoding="utf-8")
                params = StdioServerParameters(
                    command=sys.executable,
                    args=[str(ROOT / "mcp_adapter/server.py")],
                    env={"SECURITY_AUDIT_REPO_ROOT": str(root),
                         "SECURITY_AUDIT_GITHUB_REPO": ""},
                )
                async with Client(params) as client:
                    response = await client.call_tool("security_preflight", {})
                    self.assertFalse(response.is_error)
                    content = response.structured_content
                    output = json.dumps(content)
                    self.assertIn(".env.local", output)
                    self.assertNotIn("DO_NOT_PRINT_SENTINEL", output)
        asyncio.run(asyncio.wait_for(probe(), timeout=20))


if __name__ == "__main__":
    unittest.main()
