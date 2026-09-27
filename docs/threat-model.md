# Threat Model

Threats include compromised edge sites, rogue intermediates, replayed or stale attestations, stale policy after partitions, revoked workloads, scope escalation, and egress to unapproved destinations. Mitigations include short time-to-live SPIFFE Verifiable Identity Documents, path-constrained validation, signed policy deltas, deny-overrides-allow evaluation, remove-wins tombstones, fail-closed high-risk tools after max staleness, and revocation-prioritized gossip.

The policy decision point does not inspect prompt content. Content-only attacks that stay within identity, scope, policy, egress, and staleness bounds are reported as out of scope for this component. The Trusted Platform Module path is labeled simulated in this repository.
