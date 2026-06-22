"""Tests for OAPPolicy YAML loading and authorization."""

from __future__ import annotations

import os
import tempfile

import pytest

from aport_agent_guardrails_agno.policy import OAPPolicy


class TestPolicyLoading:
    def test_load_valid_yaml(self) -> None:
        yaml_content = """
version: "1.0"
agent: "test-agent"
tools:
  allowed:
    - name: "web_search"
      max_calls_per_session: 20
    - name: "read_file"
      paths: ["./data/**"]
  denied:
    - "bash"
    - "delete_file"
audit:
  receipts: true
  destination: "./oap-receipts/"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            path = f.name

        try:
            policy = OAPPolicy.from_yaml(path)
            assert policy.version == "1.0"
            assert policy.agent == "test-agent"
            assert len(policy.allowed_tools) == 2
            assert len(policy.denied_tools) == 2
            assert policy.audit_receipts is True
            assert policy.audit_destination == "./oap-receipts/"
        finally:
            os.unlink(path)

    def test_missing_file_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            OAPPolicy.from_yaml("/nonexistent/policy.yaml")

    def test_empty_yaml_raises(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("")
            path = f.name

        try:
            with pytest.raises(ValueError, match="empty or invalid YAML"):
                OAPPolicy.from_yaml(path)
        finally:
            os.unlink(path)

    def test_invalid_yaml_raises(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("[not, a, mapping]")
            path = f.name

        try:
            with pytest.raises(ValueError, match="must be a YAML mapping"):
                OAPPolicy.from_yaml(path)
        finally:
            os.unlink(path)

    def test_malformed_tool_entry_raises(self) -> None:
        yaml_content = """
version: "1.0"
tools:
  allowed:
    - 12345
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            path = f.name

        try:
            with pytest.raises(ValueError, match="Invalid allowed tool entry"):
                OAPPolicy.from_yaml(path)
        finally:
            os.unlink(path)


class TestAuthorization:
    @pytest.fixture
    def policy(self) -> OAPPolicy:
        yaml_content = """
version: "1.0"
agent: "test-agent"
tools:
  allowed:
    - name: "web_search"
      max_calls_per_session: 20
    - name: "read_file"
      paths: ["./data/**", "./docs/**"]
  denied:
    - "bash"
    - "delete_file"
    - "execute_*"
default_allow: false
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            path = f.name

        policy = OAPPolicy.from_yaml(path)
        os.unlink(path)
        return policy

    def test_allowed_tool(self, policy: OAPPolicy) -> None:
        decision = policy.authorize(tool="web_search", args={"query": "AI"}, agent="test")
        assert decision.allowed is True
        assert decision.tool == "web_search"
        assert "web_search" in decision.reason

    def test_denied_tool(self, policy: OAPPolicy) -> None:
        decision = policy.authorize(tool="bash", args={"cmd": "rm -rf /"}, agent="test")
        assert decision.allowed is False
        assert "bash" in decision.reason

    def test_denied_wildcard(self, policy: OAPPolicy) -> None:
        decision = policy.authorize(tool="execute_python", args={}, agent="test")
        assert decision.allowed is False
        assert "execute_*" in decision.reason

    def test_unknown_tool_denied_by_default(self, policy: OAPPolicy) -> None:
        decision = policy.authorize(tool="unknown_tool", args={}, agent="test")
        assert decision.allowed is False
        assert "not in allowed list" in decision.reason

    def test_path_restriction_allowed(self, policy: OAPPolicy) -> None:
        decision = policy.authorize(
            tool="read_file", args={"path": "./data/test.txt"}, agent="test"
        )
        assert decision.allowed is True

    def test_path_restriction_denied(self, policy: OAPPolicy) -> None:
        decision = policy.authorize(tool="read_file", args={"path": "/etc/passwd"}, agent="test")
        assert decision.allowed is False
        assert "path" in decision.reason

    def test_default_allow_true(self) -> None:
        yaml_content = """
version: "1.0"
tools:
  allowed: []
  denied: []
default_allow: true
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            path = f.name

        try:
            policy = OAPPolicy.from_yaml(path)
            decision = policy.authorize(tool="anything", args={}, agent="test")
            assert decision.allowed is True
            assert "default policy" in decision.reason
        finally:
            os.unlink(path)

    def test_no_args(self, policy: OAPPolicy) -> None:
        decision = policy.authorize(tool="web_search")
        assert decision.allowed is True
