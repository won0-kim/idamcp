from __future__ import annotations

import ida_idaapi
import ida_kernwin

from idamcp import config, ui
from idamcp.server import McpServerRunner


class IdaMcpPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "MCP Server for IDA Python"
    help = "Exposes IDA Python execution via MCP over Streamable HTTP"
    wanted_name = "IDAMCP"
    wanted_hotkey = "Ctrl-Shift-M"
    _server: McpServerRunner | None = None

    def init(self) -> int:
        ui.set_plugin(self)
        ui.register_actions()
        self.restart_server()
        return ida_idaapi.PLUGIN_KEEP

    def restart_server(self) -> None:
        if self._server and self._server.is_running:
            self._server.stop()
            ida_kernwin.msg("[IDAMCP] Server stopped\n")

        cfg = config.load()

        idb_path = config.get_idb_path()
        assignments = config.get_port_assignments(cfg)
        reserved_ports = config.get_reserved_ports(cfg)

        if idb_path and idb_path in assignments:
            a = assignments[idb_path]
            host = a["host"]
            port = a["port"]
            fixed = True
        else:
            host = config.get_host(cfg)
            port = config.get_port(cfg)
            fixed = False

        self._server = McpServerRunner(
            host, port, reserved_ports=reserved_ports, fixed_port=fixed,
        )
        self._server.start()

    def run(self, arg: int) -> bool:
        if self._server and self._server.is_running:
            self._server.stop()
            ida_kernwin.msg("[IDAMCP] Server stopped\n")
        else:
            self.restart_server()
        return True

    def term(self) -> None:
        ui.unregister_actions()
        if self._server and self._server.is_running:
            self._server.stop()
            ida_kernwin.msg("[IDAMCP] Server stopped\n")


def PLUGIN_ENTRY() -> IdaMcpPlugin:
    return IdaMcpPlugin()
