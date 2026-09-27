# Claims tested

Generated from `results/benchmark-dev`, `results/benchmark-test`, `results/ablation.json`, and the retained version 1 run in `results/20260926T064742Z-local`.

## Mesh security scope

| Mesh can stop | Evidence in this repository |
|---|---|
| Invalid workload identity, invalid attestation, missing tool scope, signed-policy deny, stale high-risk policy, and external egress | Existing policy decision point tests and simulator tests |
| Authority amplification across hops | The sidecar compares the requested tool against the originating task scope and requester role before allowing high-authority tools |
| Untrusted content attempting to create a delegated high-risk action | The sidecar treats retrieved documents, tool output, and Model Context Protocol server content as tainted and denies control-language delegation to egress or high-risk tools |
| Raw secret egress | The sidecar blocks exact issued secrets from the vault hook and generic encoded or high-entropy credential forms in egress sinks |

| Out of scope or only partly covered | Reason |
|---|---|
| Pure parser confusion that never leaves the allowed identity, tool, task, and egress envelope | A network and identity mesh does not fully parse model streams |
| Tool hijack that uses an allowed role, allowed task, allowed tool, and allowed destination | No mesh-layer boundary is crossed |
| Semantic prompt classification beyond request-level authority and taint | This implementation is not a prompt firewall |

## Claim to measurement table

| Claim | Measured result | Verdict |
|---|---:|---|
| 100% attack blocking | 87.4% [84.2%, 90.0%] on the test split | Not met; remaining misses are mostly parser-confusion and tool-hijack cases inside the allowed envelope |
| 0 secret leaks | 0 / 1000 traces, leak rate 0.0% [0.0%, 0.4%] with issued secrets provided and not provided | Met on this benchmark |
| False-positive rate at or below 2% | 1.6% [0.8%, 3.1%] | Point estimate met; Wilson upper bound is above 2% because only 500 benign traces are available |
| Low decision latency | p95 8.750 ms in the final official test report; ablation run p95 6.337 ms [5.965, 6.821] | Met for a local Python sidecar |

## Official evaluator results

The final numbers come from `zero_trust_agent_benchmark.evaluate.evaluate(defense, traces, provide_issued_secrets=...)`.

| Setting | Block rate | False-positive rate | Leaks / leak rate | In-policy block | Out-of-policy block |
|---|---:|---:|---:|---:|---:|
| provide issued secrets = true | 87.4% [84.2%, 90.0%] | 1.6% [0.8%, 3.1%] | 0 / 0.0% [0.0%, 0.4%] | 76.4% [70.8%, 81.2%] | 98.4% [96.0%, 99.4%] |
| provide issued secrets = false | 87.4% [84.2%, 90.0%] | 1.6% [0.8%, 3.1%] | 0 / 0.0% [0.0%, 0.4%] | 76.4% [70.8%, 81.2%] | 98.4% [96.0%, 99.4%] |

## Ablation on the test split

| Version | Block rate | False positive rate | Leaks / leak rate | p95 latency ms |
|---|---:|---:|---:|---:|
| version 1: identity, scope, policy, egress allow-list, staleness | 48.8% [44.4%, 53.2%] | 0.8% [0.3%, 2.0%] | 50 / 5.0% [3.8%, 6.5%] | 42.457 [38.803, 45.265] |
| + secret-egress detection | 58.8% [54.4%, 63.0%] | 1.6% [0.8%, 3.1%] | 0 / 0.0% [0.0%, 0.4%] | 6.609 [6.330, 7.046] |
| + untrusted-origin delegation checks | 85.0% [81.6%, 87.9%] | 1.6% [0.8%, 3.1%] | 0 / 0.0% [0.0%, 0.4%] | 6.245 [5.944, 6.531] |
| final: task-scope authority checks | 87.4% [84.2%, 90.0%] | 1.6% [0.8%, 3.1%] | 0 / 0.0% [0.0%, 0.4%] | 6.337 [5.965, 6.821] |

## Dev split miss analysis used for tuning

Before the changes, dev misses were concentrated in in-policy attacks: prompt injection 23, data exfiltration 25, control token 15, parser confusion 10, privilege escalation 23, tool hijack 15, and tool poisoning 30. The only dev leaks were 25 in-policy data-exfiltration traces. After the changes, dev block rate is 87.2% [82.5%, 90.8%], false-positive rate is 1.6% [0.6%, 4.0%], and leaks are zero.

## Regression evidence

`tests/test_sidecar_controls.py::test_no_label_or_metadata_fields_affect_decisions` randomizes labels, families, descriptions, template identifiers, split names, metadata, trace identifiers, and malicious flags while preserving request-visible fields; decisions are byte-identical. `tests/test_no_generator_markers.py` scans the enforcement source for benchmark generator markers and exact secret prefixes. Mutation-style and property tests cover paraphrased untrusted delegation, task-scope authority amplification, high-entropy secret egress, and broker secret references.

## Remaining gaps

| Gap | Reason |
|---|---|
| Test block rate is not 100% | A mesh can only enforce identity, policy, task, taint, and egress boundaries; some attacks stay inside those boundaries |
| Parser-confusion block rate is 60.0% | Full model-stream parser hardening belongs in the caller or tool runtime |
| Tool-hijack block rate is 68.3% | Some hijacks use allowed tools and destinations without carrying detectable sidecar-level authority changes |
| Hard-negative benign false positives remain | The sidecar fails closed on a small number of ambiguous benign traces to preserve zero leaks |

Temporal Logic of Actions model checker result remains 145585 generated states, 11024 distinct states, depth 10, and no violations.
