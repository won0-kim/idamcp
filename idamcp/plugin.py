from __future__ import annotations

import ida_idaapi
import ida_kernwin

from idamcp.server import DEFAULT_HOST, DEFAULT_PORT, McpServerRunner


class IdaMcpPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "MCP Server for IDA Python"
    help = "Exposes IDA Python execution via MCP over SSE"
    wanted_name = "IDAMCP"
    wanted_hotkey = "Ctrl-Shift-M"

    def init(self) -> int:
        self._server = McpServerRunner(DEFAULT_HOST, DEFAULT_PORT)
        self._server.start()
        ida_kernwin.msg(f"[IDAMCP] Server started at http://{DEFAULT_HOST}:{DEFAULT_PORT}/sse\n")
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg: int) -> bool:
        if self._server.is_running:
            self._server.stop()
            ida_kernwin.msg("[IDAMCP] Server stopped\n")
        else:
            self._server.start()
            ida_kernwin.msg(
                f"[IDAMCP] Server started at http://{DEFAULT_HOST}:{DEFAULT_PORT}/sse\n"
            )
        return True

    def term(self) -> None:
        if self._server and self._server.is_running:
            self._server.stop()
            ida_kernwin.msg("[IDAMCP] Server stopped\n")


def PLUGIN_ENTRY() -> IdaMcpPlugin:
    return IdaMcpPlugin()
