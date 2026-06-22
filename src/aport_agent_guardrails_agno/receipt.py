"""OAP Receipt generation for audit trails."""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .policy import OAPDecision


@dataclass
class OAPReceipt:
    """Auditable receipt for an OAP authorization decision."""

    id: str
    timestamp: str
    agent_id: Optional[str]
    tool: str
    decision: str
    reason: Optional[str] = None
    args: Optional[Dict[str, Any]] = None
    passport: Optional[str] = None
    policy: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def approved(
        cls,
        decision: OAPDecision,
        passport: Optional[str] = None,
        policy: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "OAPReceipt":
        """Generate an approval receipt."""
        return cls(
            id=_generate_id(),
            timestamp=_now_iso(),
            agent_id=decision.agent,
            tool=decision.tool,
            decision="approved",
            reason=decision.reason,
            args=decision.args,
            passport=passport,
            policy=policy,
            metadata=metadata or {},
        )

    @classmethod
    def denied(
        cls,
        decision: OAPDecision,
        passport: Optional[str] = None,
        policy: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "OAPReceipt":
        """Generate a denial receipt."""
        return cls(
            id=_generate_id(),
            timestamp=_now_iso(),
            agent_id=decision.agent,
            tool=decision.tool,
            decision="denied",
            reason=decision.reason,
            args=decision.args,
            passport=passport,
            policy=policy,
            metadata=metadata or {},
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize receipt to a dictionary."""
        return asdict(self)

    def to_json(self) -> str:
        """Serialize receipt to JSON string."""
        import json

        return json.dumps(self.to_dict(), indent=2)


def _generate_id() -> str:
    """Generate a unique receipt ID."""
    return f"oap_{uuid.uuid4().hex[:16]}"


def _now_iso() -> str:
    """Current timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat()
