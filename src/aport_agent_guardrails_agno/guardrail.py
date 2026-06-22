"""Agno integration for OAP guardrails.

Provides both tool-level authorization (via wrapping) and input-level
guardrails (via Agno's BaseGuardrail subclass) with fallback to local
YAML policy when the APort API is unreachable.
"""

from __future__ import annotations

import json
import os
from typing import Any, Callable, Dict, List, Optional, Union

from .policy import OAPDecision, OAPPolicy
from .receipt import OAPReceipt

# Optional Agno import — guardrail works without it for standalone use
try:
    from agno.guardrails import BaseGuardrail
    from agno.run.agent import RunInput
    from agno.run.team import TeamRunInput

    AGNO_AVAILABLE = True
except ImportError:
    AGNO_AVAILABLE = False

    # Stubs for type checking when Agno is not installed
    class BaseGuardrail:  # type: ignore[no-redef]
        pass

    RunInput = Any  # type: ignore[misc,assignment]
    TeamRunInput = Any  # type: ignore[misc,assignment]


try:
    import requests

    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class OAPAuthorizationError(PermissionError):
    """Raised when OAP policy denies a tool call."""

    def __init__(
        self,
        message: str,
        *,
        receipt: Optional[OAPReceipt] = None,
        tool: Optional[str] = None,
        reason: Optional[str] = None,
    ):
        super().__init__(message)
        self.receipt = receipt
        self.tool = tool or "unknown"
        self.reason = reason or "Authorization denied by OAP policy"


class _OAPClient:
    """Internal client for APort API verification."""

    def __init__(
        self,
        api_endpoint: str = "https://api.aport.io/v1/verify",
        api_key: Optional[str] = None,
        timeout_ms: int = 5000,
    ):
        self.api_endpoint = api_endpoint
        self.api_key = api_key
        self.timeout_ms = timeout_ms

    def verify(
        self,
        tool: str,
        args: Optional[Dict[str, Any]] = None,
        agent_id: Optional[str] = None,
    ) -> Optional[OAPDecision]:
        """Call APort API for remote authorization."""
        if not REQUESTS_AVAILABLE:
            return None

        payload: Dict[str, Any] = {
            "tool": tool,
            "args": args or {},
        }
        if agent_id:
            payload["agent_id"] = agent_id

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        try:
            response = requests.post(
                self.api_endpoint,
                headers=headers,
                data=json.dumps(payload),
                timeout=self.timeout_ms / 1000,
            )
            response.raise_for_status()
            data = response.json()

            return OAPDecision(
                allowed=bool(data.get("allow", False)),
                tool=tool,
                agent=agent_id,
                reason=data.get("reason"),
                args=args,
            )
        except Exception:
            # Fail open to local policy on API error
            return None


class AgnoToolGuardrail:
    """Tool-level guardrail for Agno agents.

    Wraps individual Agno tools (Toolkit, Function, or plain callables)
    to enforce OAP authorization on every invocation.

    Example:
        guardrail = AgnoToolGuardrail(policy_path="./oap-policy.yaml")
        wrapped_tool = guardrail.wrap_tool(my_tool)
        result = wrapped_tool(query="hello")
    """

    def __init__(
        self,
        policy_path: Optional[str] = None,
        api_endpoint: Optional[str] = None,
        api_key: Optional[str] = None,
        agent_id: Optional[str] = None,
        fallback_on_failure: str = "deny",
        timeout_ms: int = 5000,
        emit_receipts: bool = True,
        on_receipt: Optional[Callable[[OAPReceipt], None]] = None,
    ):
        self.policy: Optional[OAPPolicy] = None
        if policy_path:
            self.policy = OAPPolicy.from_yaml(policy_path)

        self.agent_id = agent_id or os.environ.get("OAP_AGENT_ID", "unknown-agent")
        self.fallback_on_failure = fallback_on_failure
        self.emit_receipts = emit_receipts
        self.on_receipt = on_receipt
        self._api_client: Optional[_OAPClient] = None

        if api_endpoint or api_key:
            self._api_client = _OAPClient(
                api_endpoint=api_endpoint or "https://api.aport.io/v1/verify",
                api_key=api_key or os.environ.get("APORT_API_KEY"),
                timeout_ms=timeout_ms,
            )

    def wrap_tool(self, tool: Any, name: Optional[str] = None) -> Any:
        """Wrap an Agno tool to enforce OAP authorization.

        Supports:
        - Callable functions
        - Agno Toolkit objects
        - Agno Function objects
        """
        tool_name = name or self._get_tool_name(tool)

        if callable(tool) and not hasattr(tool, "functions"):
            return self._wrap_callable(tool, tool_name)

        if hasattr(tool, "run") and callable(getattr(tool, "run")):
            return self._wrap_toolkit(tool, tool_name)

        if hasattr(tool, "entrypoint") and callable(getattr(tool, "entrypoint")):
            return self._wrap_function(tool, tool_name)

        # Fallback: assume duck-typed callable
        if callable(tool):
            return self._wrap_callable(tool, tool_name)

        raise TypeError(f"Unsupported tool type: {type(tool)}")

    def _get_tool_name(self, tool: Any) -> str:
        if hasattr(tool, "name") and tool.name:
            return str(tool.name)
        if hasattr(tool, "__name__"):
            return str(tool.__name__)
        return "unknown-tool"

    def _wrap_callable(self, tool: Callable[..., Any], tool_name: str) -> Callable[..., Any]:
        import functools

        @functools.wraps(tool)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            args_dict = self._build_args_dict(args, kwargs)
            self._authorize(tool_name, args_dict)
            return tool(*args, **kwargs)

        return wrapper

    def _wrap_toolkit(self, toolkit: Any, tool_name: str) -> Any:
        """Wrap an Agno Toolkit by wrapping each of its functions."""
        if not hasattr(toolkit, "functions"):
            return toolkit

        original_funcs = dict(toolkit.functions)
        for func_name, func_obj in original_funcs.items():
            if hasattr(func_obj, "entrypoint") and callable(func_obj.entrypoint):
                func_obj.entrypoint = self._wrap_callable(
                    func_obj.entrypoint, f"{tool_name}.{func_name}"
                )
            elif callable(func_obj):
                toolkit.functions[func_name] = self._wrap_callable(
                    func_obj, f"{tool_name}.{func_name}"
                )

        # Also wrap the toolkit's run method if present
        if hasattr(toolkit, "run") and callable(toolkit.run):
            toolkit.run = self._wrap_callable(toolkit.run, tool_name)

        return toolkit

    def _wrap_function(self, func: Any, tool_name: str) -> Any:
        if hasattr(func, "entrypoint") and callable(func.entrypoint):
            func.entrypoint = self._wrap_callable(func.entrypoint, tool_name)
        return func

    def _build_args_dict(self, args: tuple, kwargs: dict) -> Dict[str, Any]:
        result: Dict[str, Any] = dict(kwargs)
        if args:
            result["_args"] = list(args)
        return result

    def _authorize(self, tool: str, args: Dict[str, Any]) -> None:
        decision = self._check(tool, args)
        if not decision.allowed:
            receipt = OAPReceipt.denied(
                decision=decision,
                policy=self.policy.agent if self.policy else None,
            )
            self._emit_receipt(receipt)
            raise OAPAuthorizationError(
                f"Tool '{tool}' blocked by OAP policy: {decision.reason}",
                receipt=receipt,
                tool=tool,
                reason=decision.reason or "Authorization denied",
            )

        receipt = OAPReceipt.approved(
            decision=decision,
            policy=self.policy.agent if self.policy else None,
        )
        self._emit_receipt(receipt)

    def _check(self, tool: str, args: Dict[str, Any]) -> OAPDecision:
        # Try API first if configured
        if self._api_client:
            api_result = self._api_client.verify(tool, args, self.agent_id)
            if api_result is not None:
                return api_result

        # Fallback to local policy
        if self.policy:
            return self.policy.authorize(tool=tool, args=args, agent=self.agent_id)

        # No policy and no API — fail according to fallback strategy
        if self.fallback_on_failure == "allow":
            return OAPDecision(
                allowed=True,
                tool=tool,
                agent=self.agent_id,
                reason="Allowed: no policy configured and fallback_on_failure=allow",
                args=args,
            )

        return OAPDecision(
            allowed=False,
            tool=tool,
            agent=self.agent_id,
            reason="Denied: no policy configured and fallback_on_failure=deny",
            args=args,
        )

    def _emit_receipt(self, receipt: OAPReceipt) -> None:
        if self.emit_receipts and self.on_receipt:
            try:
                self.on_receipt(receipt)
            except Exception:
                pass


class OAPGuardrail(BaseGuardrail):
    """Agno BaseGuardrail subclass for input-level OAP checks.

    Inspects RunInput messages for tool_call intents and validates
    them against OAP policy before the model executes them.

    Note: Agno's BaseGuardrail operates on user input, not tool
    execution. For per-tool-call authorization, use AgnoToolGuardrail.
    """

    def __init__(
        self,
        policy_path: Optional[str] = None,
        api_endpoint: Optional[str] = None,
        api_key: Optional[str] = None,
        agent_id: Optional[str] = None,
        name: str = "oap_guardrail",
    ):
        if not AGNO_AVAILABLE:
            raise ImportError("Agno is not installed. Install it with: pip install agno")

        self._guardrail_name = name
        self._tool_guardrail = AgnoToolGuardrail(
            policy_path=policy_path,
            api_endpoint=api_endpoint,
            api_key=api_key,
            agent_id=agent_id,
        )

    @property
    def guardrail_name(self) -> str:
        return self._guardrail_name

    def check(self, run_input: Union[RunInput, TeamRunInput]) -> None:
        """Synchronous input check.

        Inspects messages in run_input for tool_calls and validates
        each against OAP policy.
        """
        messages = self._extract_messages(run_input)
        for msg in messages:
            if isinstance(msg, dict):
                tool_calls = msg.get("tool_calls")
            else:
                tool_calls = getattr(msg, "tool_calls", None)
            if not tool_calls:
                continue

            for tc in tool_calls:
                if isinstance(tc, dict):
                    tool_name = tc.get("name", "unknown")
                    if tool_name == "unknown":
                        fn = tc.get("function", {})
                        tool_name = fn.get("name", "unknown")
                    args = tc.get("args") or tc.get("arguments")
                    if not args:
                        fn = tc.get("function", {})
                        args = fn.get("arguments", {})
                else:
                    tool_name = getattr(tc, "name", "unknown")
                    args = getattr(tc, "args", {}) or getattr(tc, "arguments", {})

                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except json.JSONDecodeError:
                        args = {"raw": args}

                decision = self._tool_guardrail._check(tool_name, args)
                if not decision.allowed:
                    receipt = OAPReceipt.denied(
                        decision=decision,
                        policy=(
                            self._tool_guardrail.policy.agent
                            if self._tool_guardrail.policy
                            else None
                        ),
                    )
                    self._tool_guardrail._emit_receipt(receipt)
                    raise OAPAuthorizationError(
                        f"Tool '{tool_name}' blocked by OAP input guardrail: {decision.reason}",
                        receipt=receipt,
                        tool=tool_name,
                        reason=decision.reason or "Authorization denied",
                    )

    async def async_check(self, run_input: Union[RunInput, TeamRunInput]) -> None:
        """Asynchronous input check.

        Currently delegates to sync check; override for async API calls.
        """
        self.check(run_input)

    def _extract_messages(self, run_input: Union[RunInput, TeamRunInput]) -> List[Any]:
        """Extract messages from RunInput for inspection."""
        if hasattr(run_input, "input_content"):
            content = run_input.input_content
            if isinstance(content, list):
                return content
            return [content]
        return []
