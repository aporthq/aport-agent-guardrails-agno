"""Tests for Agno guardrail integration."""

from __future__ import annotations

import os
import tempfile
from typing import Any, List
from unittest.mock import MagicMock

import pytest

from aport_agent_guardrails_agno.guardrail import (
    AgnoToolGuardrail,
    OAPAuthorizationError,
    OAPGuardrail,
)


@pytest.fixture
def sample_policy_path() -> str:
    yaml_content = """
version: "1.0"
agent: "test-agent"
tools:
  allowed:
    - name: "safe_tool"
    - name: "read_file"
      paths: ["./data/**"]
  denied:
    - "dangerous_tool"
    - "delete_*"
audit:
  receipts: true
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(yaml_content)
        path = f.name

    yield path
    os.unlink(path)


class TestAgnoToolGuardrail:
    def test_allow_flow(self, sample_policy_path: str) -> None:
        guardrail = AgnoToolGuardrail(policy_path=sample_policy_path)

        @guardrail.wrap_tool
        def safe_tool(query: str) -> str:
            return f"result: {query}"

        result = safe_tool(query="hello")
        assert result == "result: hello"

    def test_deny_flow(self, sample_policy_path: str) -> None:
        guardrail = AgnoToolGuardrail(policy_path=sample_policy_path)

        @guardrail.wrap_tool
        def dangerous_tool(cmd: str) -> str:
            return f"ran: {cmd}"

        with pytest.raises(OAPAuthorizationError) as exc_info:
            dangerous_tool(cmd="rm -rf /")

        assert exc_info.value.tool == "dangerous_tool"
        assert "blocked by OAP policy" in str(exc_info.value)
        assert exc_info.value.receipt is not None
        assert exc_info.value.receipt.decision == "denied"

    def test_wildcard_deny(self, sample_policy_path: str) -> None:
        guardrail = AgnoToolGuardrail(policy_path=sample_policy_path)

        @guardrail.wrap_tool
        def delete_everything() -> None:
            pass

        with pytest.raises(OAPAuthorizationError):
            delete_everything()

    def test_missing_policy_file(self) -> None:
        with pytest.raises(FileNotFoundError):
            AgnoToolGuardrail(policy_path="/nonexistent/policy.yaml")

    def test_receipt_callback(self, sample_policy_path: str) -> None:
        receipts: List[Any] = []

        def on_receipt(receipt: Any) -> None:
            receipts.append(receipt)

        guardrail = AgnoToolGuardrail(
            policy_path=sample_policy_path,
            on_receipt=on_receipt,
        )

        @guardrail.wrap_tool
        def safe_tool() -> str:
            return "ok"

        safe_tool()
        assert len(receipts) == 1
        assert receipts[0].decision == "approved"

    def test_receipt_callback_on_deny(self, sample_policy_path: str) -> None:
        receipts: List[Any] = []

        def on_receipt(receipt: Any) -> None:
            receipts.append(receipt)

        guardrail = AgnoToolGuardrail(
            policy_path=sample_policy_path,
            on_receipt=on_receipt,
        )

        @guardrail.wrap_tool
        def dangerous_tool() -> str:
            return "bad"

        with pytest.raises(OAPAuthorizationError):
            dangerous_tool()

        assert len(receipts) == 1
        assert receipts[0].decision == "denied"

    def test_no_policy_fallback_deny(self) -> None:
        guardrail = AgnoToolGuardrail(fallback_on_failure="deny")

        @guardrail.wrap_tool
        def any_tool() -> str:
            return "ok"

        with pytest.raises(OAPAuthorizationError):
            any_tool()

    def test_no_policy_fallback_allow(self) -> None:
        guardrail = AgnoToolGuardrail(fallback_on_failure="allow")

        @guardrail.wrap_tool
        def any_tool() -> str:
            return "ok"

        result = any_tool()
        assert result == "ok"

    def test_network_failure_fallback(self, sample_policy_path: str) -> None:
        """Simulate API failure falling back to local policy."""
        guardrail = AgnoToolGuardrail(
            policy_path=sample_policy_path,
            api_endpoint="http://localhost:99999/invalid",
            timeout_ms=100,
        )

        @guardrail.wrap_tool
        def safe_tool() -> str:
            return "ok"

        result = safe_tool()
        assert result == "ok"

    def test_toolkit_wrapper(self, sample_policy_path: str) -> None:
        """Test wrapping a mock Agno Toolkit."""
        guardrail = AgnoToolGuardrail(policy_path=sample_policy_path)

        toolkit = MagicMock()
        toolkit.name = "MyToolkit"
        toolkit.functions = {
            "safe_tool": MagicMock(entrypoint=lambda x: f"safe: {x}"),
            "dangerous_tool": MagicMock(entrypoint=lambda x: f"danger: {x}"),
        }

        wrapped = guardrail.wrap_tool(toolkit)
        # Toolkit functions should be wrapped
        assert wrapped is toolkit

    def test_path_restriction(self, sample_policy_path: str) -> None:
        guardrail = AgnoToolGuardrail(policy_path=sample_policy_path)

        @guardrail.wrap_tool
        def read_file(path: str) -> str:
            return f"content of {path}"

        result = read_file(path="./data/test.txt")
        assert result == "content of ./data/test.txt"

        with pytest.raises(OAPAuthorizationError):
            read_file(path="/etc/passwd")


class TestOAPGuardrailBaseGuardrail:
    def test_import_without_agno(self) -> None:
        """OAPGuardrail should raise ImportError if Agno is not installed."""
        import aport_agent_guardrails_agno.guardrail as guardrail_module

        original = guardrail_module.AGNO_AVAILABLE
        try:
            guardrail_module.AGNO_AVAILABLE = False
            with pytest.raises(ImportError, match="Agno is not installed"):
                OAPGuardrail(policy_path="/dev/null")
        finally:
            guardrail_module.AGNO_AVAILABLE = original

    def test_check_with_tool_calls(self, sample_policy_path: str) -> None:
        """Test input guardrail that detects tool_calls in messages."""
        import aport_agent_guardrails_agno.guardrail as guardrail_module

        if not guardrail_module.AGNO_AVAILABLE:
            pytest.skip("Agno not installed")

        guardrail = OAPGuardrail(policy_path=sample_policy_path)

        # Mock RunInput with messages containing tool_calls
        mock_msg = MagicMock()
        mock_msg.tool_calls = [
            {"name": "safe_tool", "args": {"query": "hello"}},
        ]

        mock_run_input = MagicMock()
        mock_run_input.input_content = [mock_msg]

        # Should not raise
        guardrail.check(mock_run_input)

    def test_check_denies_blocked_tool(self, sample_policy_path: str) -> None:
        """Test input guardrail denies blocked tool calls."""
        import aport_agent_guardrails_agno.guardrail as guardrail_module

        if not guardrail_module.AGNO_AVAILABLE:
            pytest.skip("Agno not installed")

        guardrail = OAPGuardrail(policy_path=sample_policy_path)

        mock_msg = MagicMock()
        mock_msg.tool_calls = [
            {"name": "dangerous_tool", "args": {"cmd": "rm -rf /"}},
        ]

        mock_run_input = MagicMock()
        mock_run_input.input_content = [mock_msg]

        with pytest.raises(OAPAuthorizationError):
            guardrail.check(mock_run_input)

    def test_async_check_delegates_to_sync(self, sample_policy_path: str) -> None:
        """async_check should delegate to check."""
        import aport_agent_guardrails_agno.guardrail as guardrail_module

        if not guardrail_module.AGNO_AVAILABLE:
            pytest.skip("Agno not installed")

        guardrail = OAPGuardrail(policy_path=sample_policy_path)

        mock_run_input = MagicMock()
        mock_run_input.input_content = []

        import asyncio

        asyncio.run(guardrail.async_check(mock_run_input))
