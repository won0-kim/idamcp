from __future__ import annotations

import json
import os
import pathlib

_CONFIG_NAME = "idamcp_config.json"


def _config_path() -> pathlib.Path:
    import ida_diskio

    return pathlib.Path(ida_diskio.get_user_idadir()) / _CONFIG_NAME


def load() -> dict:
    path = _config_path()
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def save(cfg: dict) -> None:
    path = _config_path()
    path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")


def get_host(cfg: dict | None = None) -> str:
    if cfg is None:
        cfg = load()
    return cfg.get("host", os.environ.get("IDAMCP_HOST", "127.0.0.1"))


def get_port(cfg: dict | None = None) -> int:
    if cfg is None:
        cfg = load()
    return int(cfg.get("port", os.environ.get("IDAMCP_PORT", 13337)))


_DEFAULT_ASSIGN_HOST = "127.0.0.1"


def _normalize_assignment(value) -> dict:
    # Backward compat: old format stored just an int port
    if isinstance(value, int):
        return {"host": _DEFAULT_ASSIGN_HOST, "port": value}
    return {
        "host": value.get("host", _DEFAULT_ASSIGN_HOST),
        "port": int(value["port"]),
    }


def get_port_assignments(cfg: dict | None = None) -> dict[str, dict]:
    """Return {idb_path: {"host": str, "port": int}} with defaults applied."""
    if cfg is None:
        cfg = load()
    return {
        name: _normalize_assignment(v)
        for name, v in cfg.get("port_assignments", {}).items()
    }


def set_port_assignment(name: str, host: str, port: int) -> None:
    cfg = load()
    cfg.setdefault("port_assignments", {})[name] = {"host": host, "port": port}
    save(cfg)


def remove_port_assignment(name: str) -> None:
    cfg = load()
    pa = cfg.get("port_assignments", {})
    if name in pa:
        del pa[name]
        save(cfg)


def get_reserved_ports(cfg: dict | None = None) -> set[int]:
    return {a["port"] for a in get_port_assignments(cfg).values()}


def get_idb_path() -> str:
    import idc

    return idc.get_idb_path() or ""
