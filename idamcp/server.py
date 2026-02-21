from __future__ import annotations

import asyncio
import logging
import os
import threading

import uvicorn
from mcp.server.fastmcp import FastMCP

# Suppress noisy pydantic validation warnings from MCP's request parsing
# (e.g. CancelTaskRequest.params.taskId Field required)
logging.getLogger("mcp.server.lowlevel").setLevel(logging.ERROR)
logging.getLogger("mcp.server").setLevel(logging.ERROR)

import ida_kernwin

from idamcp.bridge import execute_ida_script, format_result


def _log_call(name: str, **kwargs: object) -> None:
    args = ", ".join(f"{k}={v}" for k, v in kwargs.items() if v)
    ida_kernwin.msg(f"[IDAMCP] {name}({args})\n")

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = int(os.environ.get("IDAMCP_PORT", "13337"))

mcp = FastMCP("idamcp")


_ADDR_PARSE = """\
def _parse_addr(s):
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    try:
        return int(s)
    except ValueError:
        import idc
        ea = idc.get_name_ea_simple(s)
        if ea != idc.BADADDR:
            return ea
        return int(s, 16)
"""


# ---------------------------------------------------------------------------
# Generic tool
# ---------------------------------------------------------------------------


@mcp.tool()
async def execute_script(code: str) -> str:
    """Execute IDA Python code on the IDA main thread and return the output.

    The code is executed via exec(). Assign to `__result__` to return a specific value.
    stdout and stderr are captured and included in the response.

    Example:
        code: "import idautils; __result__ = list(idautils.Functions())[:5]"
    """
    _log_call("execute_script")
    result = await execute_ida_script(code)
    return format_result(result)


# ---------------------------------------------------------------------------
# Information retrieval tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def get_function_list(filter_pattern: str = "", limit: int = 100) -> str:
    """List all functions in the binary.

    Returns JSON array of {"address": "0x...", "name": "..."}.

    Args:
        filter_pattern: Glob pattern to filter function names (e.g. "sub_*", "*main*").
        limit: Maximum number of results to return (default 100, 0 for all).
    """
    _log_call("get_function_list", filter=filter_pattern, limit=limit)
    code = """
import json, idautils, idc
functions = []
for ea in idautils.Functions():
    functions.append({"address": hex(ea), "name": idc.get_func_name(ea)})
"""
    if filter_pattern:
        code += f"""
import fnmatch
functions = [f for f in functions if fnmatch.fnmatch(f["name"], {filter_pattern!r})]
"""
    if limit:
        code += f"functions = functions[:{limit!r}]\n"
    code += "__result__ = json.dumps(functions)\n"
    result = await execute_ida_script(code)
    return format_result(result)


@mcp.tool()
async def decompile(address: str) -> str:
    """Decompile a function at the given address to pseudocode using Hex-Rays.

    Args:
        address: Function address as hex string (e.g. "0x401000") or function name.
    """
    _log_call("decompile", address=address)
    code = _ADDR_PARSE + f"""
import ida_funcs, ida_lines
try:
    import ida_hexrays
except ImportError:
    __result__ = "Error: Hex-Rays decompiler is not available."
else:
    addr = _parse_addr({address!r})
    func = ida_funcs.get_func(addr)
    if func is None:
        __result__ = f"Error: No function found at address {{hex(addr)}}"
    else:
        try:
            cfunc = ida_hexrays.decompile(func.start_ea)
            lines = cfunc.get_pseudocode()
            __result__ = "\\n".join(ida_lines.tag_remove(l.line) for l in lines)
        except ida_hexrays.DecompilationFailure as e:
            __result__ = f"Error: Decompilation failed: {{e}}"
"""
    result = await execute_ida_script(code)
    return format_result(result)


@mcp.tool()
async def get_disassembly(address: str, count: int = 30) -> str:
    """Get disassembly listing starting at address.

    Args:
        address: Start address (hex string or name).
        count: Number of instructions to disassemble (default 30).
    """
    _log_call("get_disassembly", address=address, count=count)
    code = _ADDR_PARSE + f"""
import idc
ea = _parse_addr({address!r})
lines = []
for _ in range({count!r}):
    if ea == idc.BADADDR:
        break
    lines.append(f"{{hex(ea)}}  {{idc.generate_disasm_line(ea, 0)}}")
    ea = idc.next_head(ea)
__result__ = "\\n".join(lines)
"""
    result = await execute_ida_script(code)
    return format_result(result)


@mcp.tool()
async def get_xrefs_to(address: str) -> str:
    """Get cross-references TO the given address.

    Returns JSON array of {"from": "0x...", "type": "...", "is_code": bool}.

    Args:
        address: Target address (hex string or name).
    """
    _log_call("get_xrefs_to", address=address)
    code = _ADDR_PARSE + f"""
import json, idautils, ida_xref
_XREF_TYPES = {{v: k for k, v in vars(ida_xref).items() if k.startswith(("fl_", "dr_"))}}
ea = _parse_addr({address!r})
xrefs = []
for x in idautils.XrefsTo(ea):
    xrefs.append({{"from": hex(x.frm), "type": _XREF_TYPES.get(x.type, str(x.type)), "is_code": bool(x.iscode)}})
__result__ = json.dumps(xrefs)
"""
    result = await execute_ida_script(code)
    return format_result(result)


@mcp.tool()
async def get_xrefs_from(address: str) -> str:
    """Get cross-references FROM the given address.

    Returns JSON array of {"to": "0x...", "type": "...", "is_code": bool}.

    Args:
        address: Source address (hex string or name).
    """
    _log_call("get_xrefs_from", address=address)
    code = _ADDR_PARSE + f"""
import json, idautils, ida_xref
_XREF_TYPES = {{v: k for k, v in vars(ida_xref).items() if k.startswith(("fl_", "dr_"))}}
ea = _parse_addr({address!r})
xrefs = []
for x in idautils.XrefsFrom(ea):
    xrefs.append({{"to": hex(x.to), "type": _XREF_TYPES.get(x.type, str(x.type)), "is_code": bool(x.iscode)}})
__result__ = json.dumps(xrefs)
"""
    result = await execute_ida_script(code)
    return format_result(result)


@mcp.tool()
async def get_strings(filter_pattern: str = "", min_length: int = 4, limit: int = 100) -> str:
    """List strings found in the binary.

    Returns JSON array of {"address": "0x...", "value": "...", "length": N}.

    Args:
        filter_pattern: Glob pattern to filter string values (e.g. "*error*", "*http*").
        min_length: Minimum string length to include (default 4).
        limit: Maximum number of results to return (default 100, 0 for all).
    """
    _log_call("get_strings", filter=filter_pattern, min_length=min_length, limit=limit)
    code = f"""
import json, idautils
strings = []
for s in idautils.Strings():
    if s.length >= {min_length!r}:
        strings.append({{"address": hex(s.ea), "value": str(s), "length": s.length}})
"""
    if filter_pattern:
        code += f"""
import fnmatch
strings = [s for s in strings if fnmatch.fnmatch(s["value"], {filter_pattern!r})]
"""
    if limit:
        code += f"strings = strings[:{limit!r}]\n"
    code += "__result__ = json.dumps(strings)\n"
    result = await execute_ida_script(code)
    return format_result(result)


@mcp.tool()
async def get_imports(filter_pattern: str = "", module: str = "", limit: int = 100) -> str:
    """List all imported functions.

    Returns JSON array of {"module": "...", "name": "...", "address": "0x...", "ordinal": N}.

    Args:
        filter_pattern: Glob pattern to filter function names (e.g. "*Create*", "Nt*").
        module: Filter by module name (e.g. "kernel32", "ntdll"). Case-insensitive.
        limit: Maximum number of results to return (default 100, 0 for all).
    """
    _log_call("get_imports", filter=filter_pattern, module=module, limit=limit)
    code = """
import json, ida_nalt

imports = []

def _cb(ea, name, ordinal):
    imports.append({"module": _cur_mod, "name": name or "", "address": hex(ea), "ordinal": ordinal})
    return True

for i in range(ida_nalt.get_import_module_qty()):
    _cur_mod = ida_nalt.get_import_module_name(i)
    ida_nalt.enum_import_names(i, _cb)
"""
    if module:
        code += f"""
imports = [i for i in imports if {module!r}.lower() in i["module"].lower()]
"""
    if filter_pattern:
        code += f"""
import fnmatch
imports = [i for i in imports if fnmatch.fnmatch(i["name"], {filter_pattern!r})]
"""
    if limit:
        code += f"imports = imports[:{limit!r}]\n"
    code += "__result__ = json.dumps(imports)\n"
    result = await execute_ida_script(code)
    return format_result(result)


@mcp.tool()
async def get_exports(filter_pattern: str = "", limit: int = 100) -> str:
    """List all exported functions/symbols.

    Returns JSON array of {"ordinal": N, "address": "0x...", "name": "..."}.

    Args:
        filter_pattern: Glob pattern to filter export names (e.g. "*Create*", "Dll*").
        limit: Maximum number of results to return (default 100, 0 for all).
    """
    _log_call("get_exports", filter=filter_pattern, limit=limit)
    code = """
import json, idautils
exports = []
for entry in idautils.Entries():
    # IDA 9.0: (index, ordinal, ea, name), older: (ordinal, ea, name)
    ordinal, ea, name = entry[-3], entry[-2], entry[-1]
    exports.append({"ordinal": ordinal, "address": hex(ea), "name": name or ""})
"""
    if filter_pattern:
        code += f"""
import fnmatch
exports = [e for e in exports if fnmatch.fnmatch(e["name"], {filter_pattern!r})]
"""
    if limit:
        code += f"exports = exports[:{limit!r}]\n"
    code += "__result__ = json.dumps(exports)\n"
    result = await execute_ida_script(code)
    return format_result(result)


@mcp.tool()
async def get_function_info(address: str) -> str:
    """Get detailed information about a function.

    Returns JSON with name, start/end address, size, flags, prototype, frame info.

    Args:
        address: Function address (hex string or name).
    """
    _log_call("get_function_info", address=address)
    code = _ADDR_PARSE + f"""
import json, ida_funcs, idc

ea = _parse_addr({address!r})
func = ida_funcs.get_func(ea)
if func is None:
    __result__ = f"Error: No function at {{hex(ea)}}"
else:
    info = {{
        "name": idc.get_func_name(func.start_ea),
        "start": hex(func.start_ea),
        "end": hex(func.end_ea),
        "size": func.end_ea - func.start_ea,
        "prototype": idc.get_type(func.start_ea) or "",
        "frame_size": idc.get_frame_size(func.start_ea),
        "local_vars_size": idc.get_frame_lvar_size(func.start_ea),
        "args_size": idc.get_frame_args_size(func.start_ea),
        "flags": hex(func.flags),
        "is_library": bool(func.flags & ida_funcs.FUNC_LIB),
        "is_thunk": bool(func.flags & ida_funcs.FUNC_THUNK),
    }}
    __result__ = json.dumps(info, indent=2)
"""
    result = await execute_ida_script(code)
    return format_result(result)


@mcp.tool()
async def get_segments() -> str:
    """List all memory segments in the binary.

    Returns JSON array of {"name": ".text", "start": "0x...", "end": "0x...",
    "size": N, "permissions": "rwx", "class": "CODE"}.
    """
    _log_call("get_segments")
    code = """
import json, idautils, idc, ida_segment

segments = []
for ea in idautils.Segments():
    seg = ida_segment.getseg(ea)
    perms = ""
    perms += "r" if seg.perm & ida_segment.SEGPERM_READ else "-"
    perms += "w" if seg.perm & ida_segment.SEGPERM_WRITE else "-"
    perms += "x" if seg.perm & ida_segment.SEGPERM_EXEC else "-"
    segments.append({
        "name": idc.get_segm_name(ea),
        "start": hex(seg.start_ea),
        "end": hex(seg.end_ea),
        "size": seg.end_ea - seg.start_ea,
        "permissions": perms,
        "class": ida_segment.get_segm_class(seg),
    })
__result__ = json.dumps(segments, indent=2)
"""
    result = await execute_ida_script(code)
    return format_result(result)


# ---------------------------------------------------------------------------
# Modification tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def rename_function(address: str, new_name: str) -> str:
    """Rename a function at the given address.

    Args:
        address: Function address (hex string or name).
        new_name: New name for the function.
    """
    _log_call("rename_function", address=address, new_name=new_name)
    code = _ADDR_PARSE + f"""
import idc
ea = _parse_addr({address!r})
if idc.set_name(ea, {new_name!r}, idc.SN_CHECK):
    __result__ = f"Renamed function at {{hex(ea)}} to {new_name!r}"
else:
    __result__ = f"Error: Failed to rename function at {{hex(ea)}} to {new_name!r}"
"""
    result = await execute_ida_script(code)
    return format_result(result)


@mcp.tool()
async def rename_variable(
    function_address: str, old_name: str, new_name: str
) -> str:
    """Rename a local variable in a decompiled function (requires Hex-Rays).

    Args:
        function_address: Address of the function containing the variable.
        old_name: Current variable name.
        new_name: New variable name.
    """
    _log_call("rename_variable", address=function_address, old=old_name, new=new_name)
    code = _ADDR_PARSE + f"""
import ida_funcs
try:
    import ida_hexrays
except ImportError:
    __result__ = "Error: Hex-Rays decompiler is not available."
else:
    ea = _parse_addr({function_address!r})
    func = ida_funcs.get_func(ea)
    if func is None:
        __result__ = f"Error: No function at {{hex(ea)}}"
    else:
        if ida_hexrays.rename_lvar(func.start_ea, {old_name!r}, {new_name!r}):
            __result__ = f"Renamed '{old_name!r}' to {new_name!r} in {{hex(func.start_ea)}}"
        else:
            cfunc = ida_hexrays.decompile(func.start_ea)
            names = [lv.name for lv in cfunc.lvars]
            __result__ = f"Error: Failed to rename. Available variables: {{names}}"
"""
    result = await execute_ida_script(code)
    return format_result(result)


@mcp.tool()
async def set_comment(address: str, comment: str, is_repeatable: bool = False) -> str:
    """Set a comment at the given address.

    Args:
        address: Target address (hex string or name).
        comment: Comment text.
        is_repeatable: If True, set as repeatable comment (shown at xref sites).
    """
    _log_call("set_comment", address=address)
    code = _ADDR_PARSE + f"""
import idc
ea = _parse_addr({address!r})
idc.set_cmt(ea, {comment!r}, {is_repeatable!r})
__result__ = f"Comment set at {{hex(ea)}}"
"""
    result = await execute_ida_script(code)
    return format_result(result)


@mcp.tool()
async def set_function_type(address: str, type_string: str) -> str:
    """Set a function's type/prototype signature.

    Args:
        address: Function address (hex string or name).
        type_string: C-style function prototype (e.g. "int __cdecl foo(int a, char *b)").
    """
    _log_call("set_function_type", address=address)
    code = _ADDR_PARSE + f"""
import idc
ea = _parse_addr({address!r})
if idc.SetType(ea, {type_string!r}):
    __result__ = f"Type set at {{hex(ea)}}: {type_string!r}"
else:
    __result__ = f"Error: Failed to set type at {{hex(ea)}}. Check syntax: {type_string!r}"
"""
    result = await execute_ida_script(code)
    return format_result(result)


class McpServerRunner:
    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
        self._host = host
        self._port = port
        self._server: uvicorn.Server | None = None
        self._thread: threading.Thread | None = None

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.is_running:
            return
        self._thread = threading.Thread(target=self._run, daemon=True, name="idamcp-server")
        self._thread.start()

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            app = mcp.sse_app()
            config = uvicorn.Config(
                app,
                host=self._host,
                port=self._port,
                log_level="warning",
            )
            self._server = uvicorn.Server(config)
            loop.run_until_complete(self._server.serve())
        finally:
            loop.close()

    def stop(self) -> None:
        if self._server:
            self._server.should_exit = True
        if self._thread:
            self._thread.join(timeout=5)
        self._server = None
        self._thread = None
