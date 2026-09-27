from __future__ import annotations

import time

from zero_trust_edge_agent_mesh.adapter import DefenseAdapter
from zero_trust_edge_agent_mesh.pdp import EdgePDP
from zero_trust_edge_agent_mesh.policy import Authority, PolicyStore
from zero_trust_edge_agent_mesh.simulator import Simulator


def _request(**overrides: object) -> dict[str, object]:
    req: dict[str, object] = {
        "trace_id": "unit",
        "step": 0,
        "agent": {
            "agent_id": "agent-1",
            "spiffe_id": "spiffe://acme.test/site/sjc/agent/agent-1",
            "svid": "valid",
            "attestation": "valid",
            "trust_history": ["benign", "benign"],
            "scopes": [
                "fs:read",
                "fs:write",
                "net:read",
                "net:write",
                "email:send",
                "calendar:write",
                "db:read",
                "secrets:read",
                "mcp:use",
            ],
            "role": "assistant",
        },
        "tool": "http.get",
        "args": {"url": "https://docs.acme.test/help"},
        "context": {"origin": "user", "content": "hello", "reasoning_tokens": 5},
        "history": [],
    }
    req.update(overrides)
    return req


def test_pdp_uses_catalog_scope_policy_identity_and_egress() -> None:
    pdp = EdgePDP()
    assert pdp.decide(_request()).decision == "allow"
    assert (
        pdp.decide(_request(args={"url": "https://collector.example.net/x"})).reason
        == "external_egress"
    )
    assert (
        pdp.decide(_request(tool="email.send", args={"to": "x@example.net"})).reason
        == "external_recipient"
    )
    assert pdp.decide(_request(tool="iam.grant", args={"role": "owner"})).reason == "scope_missing"
    assert pdp.decide(_request(tool="unknown.tool")).reason == "unknown_tool"
    weak = dict(_request()["agent"])
    weak["svid"] = "expired"
    assert pdp.decide(_request(agent=weak)).reason == "expired"


def test_stale_high_risk_fails_closed_but_low_risk_continues() -> None:
    pdp = EdgePDP(stale_after_s=1)
    pdp.cache_updated_s = time.time() - 5
    assert (
        pdp.decide(_request(tool="email.send", args={"to": "ops@acme.test"})).reason
        == "stale_high_risk"
    )
    assert (
        pdp.decide(_request(tool="http.get", args={"url": "https://api.acme.test/x"})).decision
        == "allow"
    )


def test_policy_and_simulator_convergence() -> None:
    auth = Authority("root")
    stores = [PolicyStore(f"n{i}", {"root": auth.public_key}) for i in range(8)]
    sim = Simulator(stores, seed=7)
    op = auth.sign_rule("spiffe://acme.test/site/*", "http.get", "allow")
    sim.inject("n0", op)
    result = sim.run_until_converged(fanout=3, loss=0.0, max_rounds=20)
    assert result.converged
    assert result.rounds <= 8


def test_defense_adapter_shape() -> None:
    dec = DefenseAdapter().decide(_request())
    assert dec == {"decision": "allow", "reason": "allowed", "component": "pdp"}
