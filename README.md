# OAP Guardrails for Agno

Deterministic pre-action authorization for [Agno](https://agno.com) AI agents via the Open Agent Protocol (OAP).

[![CI](https://github.com/aporthq/aport-agent-guardrails-agno/actions/workflows/ci.yml/badge.svg)](https://github.com/aporthq/aport-agent-guardrails-agno/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/aport-agent-guardrails-agno)](https://pypi.org/project/aport-agent-guardrails-agno/)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

## Quick Start

```bash
pip install aport-agent-guardrails-agno
```

```python
from agno.agent import Agent
from agno.tools.duckduckgo import DuckDuckGoTools
from aport_agent_guardrails_agno import AgnoToolGuardrail

# Initialize guardrail with local YAML policy
guardrail = AgnoToolGuardrail(policy_path="./oap-policy.yaml")

# Wrap tools before passing to the agent
safe_search = guardrail.wrap_tool(DuckDuckGoTools())

agent = Agent(
    name="ResearchAgent",
    tools=[safe_search],
)

agent.run("Search for latest AI safety research")
```

## Policy YAML

Create an `oap-policy.yaml` file:

```yaml
version: "1.0"
agent: "research-agent"
tools:
  allowed:
    - name: "web_search"
      max_calls_per_session: 20
    - name: "read_file"
      paths: ["./data/**"]
  denied:
    - "bash"
    - "delete_file"
    - "execute_*"
audit:
  receipts: true
  destination: "./oap-receipts/"
```

## API-Based Verification

For remote policy evaluation via the APort API:

```python
guardrail = AgnoToolGuardrail(
    policy_path="./oap-policy.yaml",          # local fallback
    api_endpoint="https://api.aport.io/v1/verify",
    api_key=os.environ["APORT_API_KEY"],
    fallback_on_failure="deny",                # "deny" | "allow" | "error"
)
```

## Input-Level Guardrail (BaseGuardrail)

If you prefer Agno's native `guardrails` list:

```python
from aport_agent_guardrails_agno import OAPGuardrail

oap_guardrail = OAPGuardrail(policy_path="./oap-policy.yaml")

agent = Agent(
    name="ResearchAgent",
    tools=[DuckDuckGoTools()],
    guardrails=[oap_guardrail],
)
```

> **Note:** `OAPGuardrail` subclasses Agno's `BaseGuardrail` and inspects incoming messages for `tool_calls`. For per-tool-call authorization, `AgnoToolGuardrail` is recommended.

## Receipts & Audit

Every authorization decision generates an auditable receipt:

```python
def on_receipt(receipt):
    print(f"{receipt.decision}: {receipt.tool} — {receipt.reason}")

guardrail = AgnoToolGuardrail(
    policy_path="./oap-policy.yaml",
    on_receipt=on_receipt,
)
```

## API Reference

### `AgnoToolGuardrail`

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `policy_path` | `str` | `None` | Path to local YAML policy file |
| `api_endpoint` | `str` | `None` | APort API endpoint URL |
| `api_key` | `str` | `None` | APort API key |
| `agent_id` | `str` | `None` | Agent identifier for receipts |
| `fallback_on_failure` | `str` | `"deny"` | Behavior when API is unreachable |
| `timeout_ms` | `int` | `5000` | API request timeout |
| `emit_receipts` | `bool` | `True` | Emit receipt callbacks |
| `on_receipt` | `Callable` | `None` | Callback for each receipt |

### `OAPPolicy`

- `OAPPolicy.from_yaml(path)` — load policy from YAML
- `policy.authorize(tool, args, agent)` → `OAPDecision`

### `OAPReceipt`

- `OAPReceipt.approved(decision)` — generate approval receipt
- `OAPReceipt.denied(decision)` — generate denial receipt
- `receipt.to_dict()` / `receipt.to_json()` — serialize

## Development

```bash
git clone https://github.com/aporthq/aport-agent-guardrails-agno.git
cd aport-agent-guardrails-agno
pip install -e ".[dev,agno]"
pytest
```

## Citation

```bibtex
@software{aport_guardrails_agno,
  title = {APort Agent Guardrails — Agno Adapter},
  author = {LiftRails Inc},
  year = {2026},
  doi = {10.5281/zenodo.18901596},
  url = {https://github.com/aporthq/aport-agent-guardrails-agno}
}
```

## License

MIT — see [LICENSE](LICENSE).
