from __future__ import annotations

import ida_kernwin

from idamcp import config

_plugin = None


def set_plugin(plugin) -> None:
    global _plugin
    _plugin = plugin


# ---------------------------------------------------------------------------
# Settings Form
# ---------------------------------------------------------------------------


class _SettingsForm(ida_kernwin.Form):
    def __init__(self, host: str, port: int, status: str):
        F = ida_kernwin.Form
        F.__init__(
            self,
            "STARTITEM 0\n"
            "BUTTON YES* Apply\n"
            "BUTTON CANCEL Cancel\n"
            "IDAMCP Settings\n"
            "\n"
            f"{status}\n"
            "\n"
            "<Host:{iHost}>\n"
            "<Port:{iPort}>\n",
            {
                "iHost": F.StringInput(value=host),
                "iPort": F.NumericInput(value=port, tp=F.FT_DEC),
            },
        )


def show_settings() -> None:
    cfg = config.load()
    host = config.get_host(cfg)
    port = config.get_port(cfg)

    if _plugin and _plugin._server and _plugin._server.is_running:
        actual_port = _plugin._server.port
        actual_host = _plugin._server.host
        status = f"Server: Running on {actual_host}:{actual_port}"
    else:
        status = "Server: Stopped"

    idb_path = config.get_idb_path()
    assignments = config.get_port_assignments(cfg)
    if idb_path and idb_path in assignments:
        a = assignments[idb_path]
        status += f"\nFile: {idb_path} (saved: {a['host']}:{a['port']})"
    elif idb_path:
        status += f"\nFile: {idb_path} (auto-allocate)"

    # Show the current IDB's host/port (assigned or running), not the base config
    if _plugin and _plugin._server and _plugin._server.is_running:
        current_host = _plugin._server.host
        current_port = _plugin._server.port
    elif idb_path and idb_path in assignments:
        current_host = assignments[idb_path]["host"]
        current_port = assignments[idb_path]["port"]
    else:
        current_host = host
        current_port = config.get_port(cfg)

    f = _SettingsForm(current_host, current_port, status)
    f.Compile()
    ok = f.Execute()
    if ok == 1:
        new_host = f.iHost.value
        new_port = f.iPort.value
        if idb_path:
            # Save host+port as this IDB's assignment
            config.set_port_assignment(idb_path, new_host, new_port)
            _notify_assignments_changed()
        else:
            # No IDB loaded — update base config
            cfg["host"] = new_host
            cfg["port"] = new_port
            config.save(cfg)
        if _plugin:
            _plugin.restart_server()
    f.Free()


# ---------------------------------------------------------------------------
# Port Assignments Chooser
# ---------------------------------------------------------------------------


class _PortAssignmentsChooser(ida_kernwin.Choose):
    def __init__(self):
        ida_kernwin.Choose.__init__(
            self,
            "IDAMCP Port Assignments",
            [["IDB Path", 60], ["Host", 15], ["Port", 10]],
            flags=(
                ida_kernwin.Choose.CH_CAN_DEL
                | ida_kernwin.Choose.CH_CAN_INS
                | ida_kernwin.Choose.CH_CAN_EDIT
            ),
        )
        self.items: list[list[str]] = []
        self._refresh()

    def _refresh(self) -> None:
        self.items = [
            [name, a["host"], str(a["port"])]
            for name, a in sorted(config.get_port_assignments().items())
        ]

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def OnDeleteLine(self, n):
        if 0 <= n < len(self.items):
            config.remove_port_assignment(self.items[n][0])
            self._refresh()
        return [ida_kernwin.Choose.ALL_CHANGED, min(n, len(self.items) - 1)]

    def OnInsertLine(self, n):
        name = ida_kernwin.ask_str("", 0, "IDB path:")
        if name:
            host = ida_kernwin.ask_str("127.0.0.1", 0, "Host:")
            if host:
                port = ida_kernwin.ask_long(13337, "Port number:")
                if port is not None and port > 0:
                    config.set_port_assignment(name, host, port)
                    self._refresh()
        return [ida_kernwin.Choose.ALL_CHANGED, n]

    def OnEditLine(self, n):
        if 0 <= n < len(self.items):
            name, old_host, old_port_s = self.items[n]
            host = ida_kernwin.ask_str(old_host, 0, f"Host for '{name}':")
            if host:
                port = ida_kernwin.ask_long(int(old_port_s), f"Port for '{name}':")
                if port is not None and port > 0:
                    config.set_port_assignment(name, host, port)
                    self._refresh()
        return [ida_kernwin.Choose.ALL_CHANGED, n]


_CHOOSER_TITLE = "IDAMCP Port Assignments"


def show_port_assignments() -> None:
    c = _PortAssignmentsChooser()
    c.Show()


def _notify_assignments_changed() -> None:
    """Refresh the Port Assignments chooser if it's currently open."""
    ida_kernwin.refresh_chooser(_CHOOSER_TITLE)


# ---------------------------------------------------------------------------
# Action handlers
# ---------------------------------------------------------------------------


class _SettingsHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        show_settings()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class _PortAssignmentsHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        show_port_assignments()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class _SavePortHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        idb_path = config.get_idb_path()
        if not idb_path:
            ida_kernwin.warning("No input file loaded.")
            return 0
        if _plugin and _plugin._server and _plugin._server.is_running:
            host = _plugin._server.host
            port = _plugin._server.port
            config.set_port_assignment(idb_path, host, port)
            _notify_assignments_changed()
            ida_kernwin.msg(
                f"[IDAMCP] Saved {host}:{port} for '{idb_path}'\n"
            )
        else:
            ida_kernwin.warning("Server is not running.")
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class _ToggleServerHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        if _plugin:
            if _plugin._server and _plugin._server.is_running:
                _plugin._server.stop()
                ida_kernwin.msg("[IDAMCP] Server stopped\n")
            else:
                _plugin.restart_server()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

_ACTIONS = [
    ("idamcp:settings", "Settings...", _SettingsHandler(), ""),
    ("idamcp:port_assignments", "Port Assignments...", _PortAssignmentsHandler(), ""),
    ("idamcp:save_port", "Save Config for This File", _SavePortHandler(), ""),
    ("idamcp:toggle", "Start/Stop Server", _ToggleServerHandler(), ""),
]

_MENU_PATH = "Edit/IDAMCP/"


def register_actions() -> None:
    for action_id, label, handler, shortcut in _ACTIONS:
        desc = ida_kernwin.action_desc_t(action_id, label, handler, shortcut, "", -1)
        ida_kernwin.register_action(desc)
        ida_kernwin.attach_action_to_menu(
            _MENU_PATH, action_id, ida_kernwin.SETMENU_APP
        )


def unregister_actions() -> None:
    for action_id, *_ in _ACTIONS:
        ida_kernwin.detach_action_from_menu(_MENU_PATH, action_id)
        ida_kernwin.unregister_action(action_id)
