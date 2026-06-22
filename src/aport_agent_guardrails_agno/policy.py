"""OAP Policy engine for local YAML-based authorization."""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import yaml


@dataclass
class OAPDecision:
    """Result of an OAP authorization check."""

    allowed: bool
    tool: str
    agent: Optional[str] = None
    reason: Optional[str] = None
    args: Optional[Dict[str, Any]] = None


@dataclass
class ToolRule:
    """Rule for a specific tool in the policy."""

    name: str
    max_calls_per_session: Optional[int] = None
    paths: Optional[List[str]] = None
    args_schema: Optional[Dict[str, Any]] = None


@dataclass
class OAPPolicy:
    """OAP policy loaded from YAML configuration."""

    version: str
    agent: Optional[str] = None
    allowed_tools: List[ToolRule] = field(default_factory=list)
    denied_tools: List[str] = field(default_factory=list)
    audit_receipts: bool = True
    audit_destination: Optional[str] = None
    default_allow: bool = False

    @classmethod
    def from_yaml(cls, policy_path: str) -> "OAPPolicy":
        """Load an OAP policy from a YAML file."""
        if not os.path.exists(policy_path):
            raise FileNotFoundError(f"OAP policy file not found: {policy_path}")

        with open(policy_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)

        if raw is None:
            raise ValueError("OAP policy file is empty or invalid YAML")

        if not isinstance(raw, dict):
            raise ValueError("OAP policy must be a YAML mapping")

        version = str(raw.get("version", "1.0"))
        agent = raw.get("agent")

        tools_section = raw.get("tools", {})
        allowed = tools_section.get("allowed", [])
        denied = tools_section.get("denied", [])

        allowed_tools: List[ToolRule] = []
        for entry in allowed:
            if isinstance(entry, str):
                allowed_tools.append(ToolRule(name=entry))
            elif isinstance(entry, dict):
                allowed_tools.append(
                    ToolRule(
                        name=entry["name"],
                        max_calls_per_session=entry.get("max_calls_per_session"),
                        paths=entry.get("paths"),
                        args_schema=entry.get("args_schema"),
                    )
                )
            else:
                raise ValueError(f"Invalid allowed tool entry: {entry}")

        denied_tools: List[str] = []
        for entry in denied:
            if isinstance(entry, str):
                denied_tools.append(entry)
            elif isinstance(entry, dict):
                denied_tools.append(entry.get("name", str(entry)))
            else:
                raise ValueError(f"Invalid denied tool entry: {entry}")

        audit_section = raw.get("audit", {})
        audit_receipts = audit_section.get("receipts", True)
        audit_destination = audit_section.get("destination")

        default_allow = raw.get("default_allow", False)

        return cls(
            version=version,
            agent=agent,
            allowed_tools=allowed_tools,
            denied_tools=denied_tools,
            audit_receipts=audit_receipts,
            audit_destination=audit_destination,
            default_allow=default_allow,
        )

    def authorize(
        self,
        tool: str,
        args: Optional[Dict[str, Any]] = None,
        agent: Optional[str] = None,
    ) -> OAPDecision:
        """Authorize a tool call against this policy."""
        # 1. Explicit deny list (highest priority)
        for pattern in self.denied_tools:
            if fnmatch.fnmatch(tool, pattern):
                return OAPDecision(
                    allowed=False,
                    tool=tool,
                    agent=agent,
                    reason=f"Tool '{tool}' matches denied pattern '{pattern}'",
                    args=args,
                )

        # 2. Explicit allow list
        for rule in self.allowed_tools:
            if fnmatch.fnmatch(tool, rule.name):
                # Check path restrictions if present
                if rule.paths and args:
                    path_arg = args.get("path") or args.get("file_path") or args.get("filename")
                    if path_arg and isinstance(path_arg, str):
                        if not any(fnmatch.fnmatch(path_arg, pattern) for pattern in rule.paths):
                            return OAPDecision(
                                allowed=False,
                                tool=tool,
                                agent=agent,
                                reason=(
                                    f"Tool '{tool}' path '{path_arg} does not match "
                                    f"allowed patterns: {rule.paths}"
                                ),
                                args=args,
                            )

                return OAPDecision(
                    allowed=True,
                    tool=tool,
                    agent=agent,
                    reason=f"Tool '{tool}' matches allowed pattern '{rule.name}'",
                    args=args,
                )

        # 3. Default policy
        if self.default_allow:
            return OAPDecision(
                allowed=True,
                tool=tool,
                agent=agent,
                reason=f"Tool '{tool}' allowed by default policy",
                args=args,
            )

        return OAPDecision(
            allowed=False,
            tool=tool,
            agent=agent,
            reason=f"Tool '{tool}' not in allowed list and default_allow is False",
            args=args,
        )
