# DSH Canary Decision Proof

Offline, deterministic evidence that a recorded canary `promote`, `abort`, or `pause` decision follows one explicit, hash-only policy.

This plugin **does not execute a rollout, query live metrics, authenticate receipts, grant authorization, prove statistical significance, or prove user outcomes**. It verifies supplied evidence and fails closed to `pause` when that evidence is incomplete.

## Boundary

- [`dsh-ankh-guard`](https://github.com/Khorsheed/dsh-ankh-guard) supervises a running DSH instance, performs a health canary, and can automatically roll back. This plugin never starts, stops, promotes, or rolls back anything.
- [`dsh-artifact-promotion-proof`](https://github.com/dongsheng123132/dsh-artifact-promotion-proof) proves an ordered artifact promotion chain. This plugin recomputes the decision immediately before such a promotion.
- [`dsh-deployment-rollback-proof`](https://github.com/dongsheng123132/dsh-deployment-rollback-proof) proves last-known-good convergence after failure. This plugin decides whether supplied canary evidence says promote, abort, or pause.
- Argo Rollouts provides a live progressive-delivery controller. This plugin is a controller-neutral, offline evidence verifier.

## Evidence model

The manifest pins canary and baseline artifact digests, environment, rollout and policy receipts, exact analysis windows, maximum canary traffic, minimum window length, observer threshold, evidence freshness, and metric rules. Every metric requires one baseline and one canary observation in every window.

Metric values are positive fixed-point integers (`valueMicros`). For `higher-better`, regression is `(baseline - canary) / baseline`; for `lower-better`, it is `(canary - baseline) / baseline`. Integer basis points make the judgment deterministic. A metric fails when breached windows reach its declared `failureLimit`.

Decision precedence is fixed:

1. incomplete, stale, unbound, under-sampled, over-exposed, or chronologically invalid evidence → `pause`;
2. otherwise any failed metric → `abort`;
3. otherwise → `promote`.

The recorded decision is verified only when it equals that computed decision.

## Use

```bash
npm test
node bin/dsh-canary-decision-proof.mjs inspect examples/promote.json
node bin/dsh-canary-decision-proof.mjs verify examples/promote.json
```

DSH exposes `dsh_canary_decision_inspect` and `dsh_canary_decision_verify`. The independent stdio MCP server exposes `canary_decision_inspect` and `canary_decision_verify`.

The DSH verifier writes only beneath an explicit workspace-relative `artifactDir`, rejects path escape and symlinks, creates a content-addressed report exclusively, and verifies it by read-back. Reports contain hashes, counts, timestamps, fixed-point comparisons, checks and verdicts—not raw business text or secrets.

See [`examples/promote.json`](examples/promote.json) and [SECURITY.md](SECURITY.md). Node.js 22 or later is required. Licensed under MIT.

