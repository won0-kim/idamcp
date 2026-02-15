from __future__ import annotations

import sys
from unittest.mock import MagicMock

ida_kernwin_mock = MagicMock()


def _fake_execute_sync(func, flags):
    func()
    return 1


ida_kernwin_mock.execute_sync = _fake_execute_sync
ida_kernwin_mock.MFF_WRITE = 0x0002
sys.modules["ida_kernwin"] = ida_kernwin_mock

from idamcp.server import mcp  # noqa: E402


class TestMcpServerTools:
    def test_execute_script_registered(self) -> None:
        tools = mcp._tool_manager.list_tools()
        tool_names = [t.name for t in tools]
        assert "execute_script" in tool_names

    def test_execute_script_has_code_param(self) -> None:
        tools = mcp._tool_manager.list_tools()
        tool = next(t for t in tools if t.name == "execute_script")
        schema = tool.parameters.get("properties", {})
        required = tool.parameters.get("required", [])
        assert "code" in schema
        assert "code" in required
