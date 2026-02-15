from __future__ import annotations

import asyncio
import io
import sys
import traceback
from dataclasses import dataclass


@dataclass
class ExecutionResult:
    success: bool
    stdout: str = ""
    stderr: str = ""
    error: str | None = None
    return_value: str | None = None


def _execute_on_main_thread(code: str) -> ExecutionResult:
    import ida_kernwin

    result_holder: list[ExecutionResult] = []

    def _runner():
        old_stdout, old_stderr = sys.stdout, sys.stderr
        captured_out, captured_err = io.StringIO(), io.StringIO()
        sys.stdout, sys.stderr = captured_out, captured_err
        try:
            exec_globals: dict[str, object] = {}
            exec(code, exec_globals)
            result_holder.append(
                ExecutionResult(
                    success=True,
                    stdout=captured_out.getvalue(),
                    stderr=captured_err.getvalue(),
                    return_value=str(exec_globals["__result__"])
                    if "__result__" in exec_globals
                    else None,
                )
            )
        except Exception:
            result_holder.append(
                ExecutionResult(
                    success=False,
                    stdout=captured_out.getvalue(),
                    stderr=captured_err.getvalue(),
                    error=traceback.format_exc(),
                )
            )
        finally:
            sys.stdout, sys.stderr = old_stdout, old_stderr
        return 1

    ida_kernwin.execute_sync(_runner, ida_kernwin.MFF_WRITE)

    if not result_holder:
        return ExecutionResult(success=False, error="execute_sync did not complete")
    return result_holder[0]


async def execute_ida_script(code: str) -> ExecutionResult:
    return await asyncio.to_thread(_execute_on_main_thread, code)


def format_result(result: ExecutionResult) -> str:
    parts: list[str] = []
    if result.return_value is not None:
        parts.append(result.return_value)
    if result.stdout:
        parts.append(result.stdout)
    if result.stderr:
        parts.append(f"[stderr]\n{result.stderr}")
    if not result.success and result.error:
        parts.append(f"[error]\n{result.error}")
    return "\n".join(parts) if parts else "(no output)"
