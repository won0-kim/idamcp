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
        status += f"\nFile: {idb_path} (saved port: {assignments[idb_path]})"
    elif idb_path:
        status += f"\nFile: {idb_path} (auto-allocate)"

    # Show the current IDB's port (assigned or running), not the base port
    idb_path = config.get_idb_path()
    assignments = config.get_port_assignments(cfg)
    if _plugin and _plugin._server and _plugin._server.is_running:
        current_port = _plugin._server.port
    elif idb_path and idb_path in assignments:
        current_port = assignments[idb_path]
    else:
        current_port = config.get_port(cfg)

    f = _SettingsForm(host, current_port, status)
    f.Compile()
    ok = f.Execute()
    if ok == 1:
        new_host = f.iHost.value
        new_port = f.iPort.value
        cfg["host"] = new_host
        config.save(cfg)
        # Save port as this IDB's assignment, not as base port
        if idb_path:
            config.set_port_assignment(idb_path, new_port)
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
            [["IDB Path", 60], ["Port", 10]],
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
            [name, str(port)]
            for name, port in sorted(config.get_port_assignments().items())
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
            port = ida_kernwin.ask_long(13337, "Port number:")
            if port is not None and port > 0:
                config.set_port_assignment(name, port)
                self._refresh()
        return [ida_kernwin.Choose.ALL_CHANGED, n]

    def OnEditLine(self, n):
        if 0 <= n < len(self.items):
            name = self.items[n][0]
            old_port = int(self.items[n][1])
            port = ida_kernwin.ask_long(old_port, f"Port for '{name}':")
            if port is not None and port > 0:
                config.set_port_assignment(name, port)
                self._refresh()
        return [ida_kernwin.Choose.ALL_CHANGED, n]


def show_port_assignments() -> None:
    c = _PortAssignmentsChooser()
    c.Show()


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
            port = _plugin._server.port
            config.set_port_assignment(idb_path, port)
            ida_kernwin.msg(f"[IDAMCP] Saved port {port} for '{idb_path}'\n")
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
    ("idamcp:save_port", "Save Port for This File", _SavePortHandler(), ""),
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
