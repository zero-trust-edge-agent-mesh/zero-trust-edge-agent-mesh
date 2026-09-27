# Changelog

## Unreleased - 2026-09-26

- Added sidecar secret-egress detection, untrusted-origin delegation checks, and task-scope authority checks.
- Added no-label-leakage, literal-guard, mutation-style, and property tests for the new sidecar controls.
- Updated benchmark artifacts: test block rate 87.4%, false-positive rate 1.6%, and zero leaks with and without issued secrets.
- Renamed internal labels and environment variables to descriptive public names.
- Renamed labels in result files; measured values unchanged.

## 0.1.0 - 2026-09-25

- Initial local release with edge SVID issuance, signed CRDT policies, PDP, simulator, TLC spec, and benchmarks.
