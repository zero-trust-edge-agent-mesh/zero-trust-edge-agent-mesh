from __future__ import annotations

import datetime as dt

from zero_trust_edge_agent_mesh.identity import EdgePKI, attestation_quote, should_rotate


def test_nested_svid_validation_and_rotation() -> None:
    now = dt.datetime(2026, 9, 25, tzinfo=dt.UTC)
    pki = EdgePKI(now=now)
    svid = pki.issue_svid("sjc", "agent-7", ttl_s=90, now=now)
    result = pki.validate_svid(svid.cert_pem, svid.chain_pem, expected_site="sjc", at_time=now)
    assert result.ok
    assert result.spiffe_id == "spiffe://acme.test/site/sjc/agent/agent-7"
    assert not should_rotate(svid.not_after, now=now, lead_s=30)
    assert should_rotate(svid.not_after, now=now + dt.timedelta(seconds=70), lead_s=30)


def test_site_constraint_and_expiry_fail_closed() -> None:
    now = dt.datetime(2026, 9, 25, tzinfo=dt.UTC)
    pki = EdgePKI(now=now)
    svid = pki.issue_svid("sfo", "agent-1", ttl_s=10, now=now)
    assert not pki.validate_svid(svid.cert_pem, svid.chain_pem, expected_site="sjc", at_time=now).ok
    expired = pki.validate_svid(
        svid.cert_pem, svid.chain_pem, at_time=now + dt.timedelta(seconds=12)
    )
    assert expired.reason == "expired"


def test_simulated_attestation_quote_is_bound_to_nonce() -> None:
    pki = EdgePKI()
    svid = pki.issue_svid("lon", "agent-1")
    quote = attestation_quote(b"nonce-1", pki.root_key)
    assert quote["nonce"] == b"nonce-1"
    assert quote["signature"] != svid.cert_pem
