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

from idamcp.bridge import ExecutionResult, _execute_on_main_thread, format_result  # noqa: E402


class TestExecuteOnMainThread:
    def test_simple_print(self) -> None:
        result = _execute_on_main_thread("print('hello')")
        assert result.success
        assert result.stdout.strip() == "hello"

    def test_return_value(self) -> None:
        result = _execute_on_main_thread("__result__ = 42")
        assert result.success
        assert result.return_value == "42"

    def test_syntax_error(self) -> None:
        result = _execute_on_main_thread("def")
        assert not result.success
        assert result.error is not None
        assert "SyntaxError" in result.error

    def test_runtime_error(self) -> None:
        result = _execute_on_main_thread("1/0")
        assert not result.success
        assert result.error is not None
        assert "ZeroDivisionError" in result.error

    def test_stderr_capture(self) -> None:
        result = _execute_on_main_thread("import sys; sys.stderr.write('warn\\n')")
        assert result.success
        assert "warn" in result.stderr

    def test_no_output(self) -> None:
        result = _execute_on_main_thread("x = 1")
        assert result.success
        assert result.stdout == ""
        assert result.return_value is None

    def test_multiline(self) -> None:
        code = "a = 1\nb = 2\n__result__ = a + b"
        result = _execute_on_main_thread(code)
        assert result.success
        assert result.return_value == "3"


class TestFormatResult:
    def test_with_return_value(self) -> None:
        r = ExecutionResult(success=True, return_value="42")
        assert format_result(r) == "42"

    def test_with_stdout(self) -> None:
        r = ExecutionResult(success=True, stdout="hello\n")
        assert format_result(r) == "hello\n"

    def test_with_error(self) -> None:
        r = ExecutionResult(success=False, error="boom")
        assert "[error]" in format_result(r)

    def test_no_output(self) -> None:
        r = ExecutionResult(success=True)
        assert format_result(r) == "(no output)"

    def test_combined(self) -> None:
        r = ExecutionResult(success=True, stdout="out\n", stderr="err\n", return_value="val")
        formatted = format_result(r)
        assert "val" in formatted
        assert "out" in formatted
        assert "[stderr]" in formatted
