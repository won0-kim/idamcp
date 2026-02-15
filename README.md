# IDAMCP

IDA Pro plugin that exposes IDA Python execution via [MCP (Model Context Protocol)](https://modelcontextprotocol.io/) over SSE. This allows AI tools like Claude Code to interact with IDA Pro for reverse engineering tasks.

## How It Works

IDAMCP runs an MCP server inside IDA Pro that provides an `execute_script` tool. AI clients send IDA Python code through MCP, which gets executed on IDA's main thread. Results (stdout, stderr, return values) are sent back to the client.

```
AI Client (Claude Code, etc.)
    │
    │  MCP over SSE
    ▼
IDAMCP Server (127.0.0.1:13337)
    │
    │  ida_kernwin.execute_sync
    ▼
IDA Pro Main Thread
```

## Requirements

- IDA Pro 9.0+
- Python 3.12+
- [uv](https://docs.astral.sh/uv/)

## Installation

```bash
git clone https://github.com/won0-kim/idamcp.git
cd idamcp
uv sync
```

Install the plugin into IDA's plugins directory:

```bash
python install.py
```

To specify a custom IDA installation path:

```bash
python install.py --ida-dir "C:\Path\To\IDA"
```

To uninstall:

```bash
python install.py --uninstall
```

## Usage

1. Open IDA Pro — the MCP server starts automatically on `http://127.0.0.1:13337/sse`
2. Toggle the server on/off with **Ctrl+Shift+M**
3. Connect your MCP client to the server

### MCP Client Configuration

Add to your MCP client config (e.g., `.mcp.json`):

```json
{
  "mcpServers": {
    "idamcp": {
      "type": "sse",
      "url": "http://127.0.0.1:13337/sse"
    }
  }
}
```

### execute_script Tool

The server exposes a single `execute_script` tool. Send IDA Python code as a string. Assign to `__result__` to return a specific value.

```python
# List first 5 functions
import idautils
__result__ = list(idautils.Functions())[:5]
```

```python
# Get function name at address
import idc
__result__ = idc.get_func_name(0x401000)
```

## Development

```bash
uv sync --all-extras
uv run pytest
uv run ruff check .
uv run ruff format .
uv run pyright
```

## Project Structure

```
idamcp/
├── idamcp/
│   ├── __init__.py      # Package version
│   ├── bridge.py        # IDA main thread execution bridge
│   ├── plugin.py        # IDA plugin entry point
│   └── server.py        # FastMCP server with execute_script tool
├── tests/
│   ├── test_bridge.py
│   └── test_server.py
├── install.py           # Development plugin installer
├── idamcp_plugin.py     # Standalone plugin entry point
└── pyproject.toml
```

## License

MIT
