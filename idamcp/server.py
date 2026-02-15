from __future__ import annotations

import asyncio
import threading

import uvicorn
from mcp.server.fastmcp import FastMCP

from idamcp.bridge import execute_ida_script, format_result

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 13337

mcp = FastMCP("idamcp")


@mcp.tool()
async def execute_script(code: str) -> str:
    """Execute IDA Python code on the IDA main thread and return the output.

    The code is executed via exec(). Assign to `__result__` to return a specific value.
    stdout and stderr are captured and included in the response.

    Example:
        code: "import idautils; __result__ = list(idautils.Functions())[:5]"
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
