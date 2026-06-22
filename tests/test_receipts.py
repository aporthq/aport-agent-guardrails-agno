"""Tests for OAPReceipt generation and serialization."""

from __future__ import annotations

import json

from aport_agent_guardrails_agno.policy import OAPDecision
from aport_agent_guardrails_agno.receipt import OAPReceipt


class TestReceiptGeneration:
    def test_approved_receipt(self) -> None:
        decision = OAPDecision(
            allowed=True,
            tool="web_search",
            agent="agent-1",
            reason="Allowed by policy",
            args={"query": "AI safety"},
        )
        receipt = OAPReceipt.approved(decision, passport="pass-1", policy="policy-1")

        assert receipt.decision == "approved"
        assert receipt.tool == "web_search"
        assert receipt.agent_id == "agent-1"
        assert receipt.reason == "Allowed by policy"
        assert receipt.args == {"query": "AI safety"}
        assert receipt.passport == "pass-1"
        assert receipt.policy == "policy-1"
        assert receipt.id.startswith("oap_")
        assert receipt.timestamp is not None

    def test_denied_receipt(self) -> None:
        decision = OAPDecision(
            allowed=False,
            tool="bash",
            agent="agent-1",
            reason="Tool denied by policy",
            args={"cmd": "rm -rf /"},
        )
        receipt = OAPReceipt.denied(decision)

        assert receipt.decision == "denied"
        assert receipt.tool == "bash"
        assert receipt.reason == "Tool denied by policy"
        assert receipt.passport is None

    def test_receipt_to_dict(self) -> None:
        decision = OAPDecision(allowed=True, tool="web_search")
        receipt = OAPReceipt.approved(decision)
        d = receipt.to_dict()

        assert isinstance(d, dict)
        assert d["decision"] == "approved"
        assert d["tool"] == "web_search"
        assert "id" in d
        assert "timestamp" in d

    def test_receipt_to_json(self) -> None:
        decision = OAPDecision(allowed=False, tool="bash", reason="Denied")
        receipt = OAPReceipt.denied(decision)
        s = receipt.to_json()

        parsed = json.loads(s)
        assert parsed["decision"] == "denied"
        assert parsed["tool"] == "bash"
