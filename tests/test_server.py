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

ALL_TOOLS = [
    "execute_script",
    "get_function_list",
    "decompile",
    "get_disassembly",
    "get_xrefs_to",
    "get_xrefs_from",
    "get_strings",
    "get_imports",
    "get_exports",
    "get_function_info",
    "get_segments",
    "rename_function",
    "rename_variable",
    "set_comment",
    "set_function_type",
]


class TestMcpServerTools:
    def test_all_tools_registered(self) -> None:
        tools = mcp._tool_manager.list_tools()
        tool_names = [t.name for t in tools]
        for name in ALL_TOOLS:
            assert name in tool_names, f"Tool {name!r} not registered"

    def test_tool_count(self) -> None:
        tools = mcp._tool_manager.list_tools()
        assert len(tools) == len(ALL_TOOLS)

    def test_execute_script_has_code_param(self) -> None:
        tools = mcp._tool_manager.list_tools()
        tool = next(t for t in tools if t.name == "execute_script")
        schema = tool.parameters.get("properties", {})
        required = tool.parameters.get("required", [])
        assert "code" in schema
        assert "code" in required

    def test_decompile_has_address_param(self) -> None:
        tools = mcp._tool_manager.list_tools()
        tool = next(t for t in tools if t.name == "decompile")
        required = tool.parameters.get("required", [])
        assert "address" in required

    def test_rename_function_params(self) -> None:
        tools = mcp._tool_manager.list_tools()
        tool = next(t for t in tools if t.name == "rename_function")
        required = tool.parameters.get("required", [])
        assert "address" in required
        assert "new_name" in required

    def test_get_function_list_filter_optional(self) -> None:
        tools = mcp._tool_manager.list_tools()
        tool = next(t for t in tools if t.name == "get_function_list")
        required = tool.parameters.get("required", [])
        props = tool.parameters.get("properties", {})
        assert "filter_pattern" not in required
        assert "filter_pattern" in props

    def test_set_comment_params(self) -> None:
        tools = mcp._tool_manager.list_tools()
        tool = next(t for t in tools if t.name == "set_comment")
        required = tool.parameters.get("required", [])
        assert "address" in required
        assert "comment" in required
