# Security Policy

## Supported version

Security fixes target the latest release on `main`.

## Trust boundary

This verifier is offline and non-destructive. It does not query a metric provider, execute rollout, authenticate receipts, grant approval, or establish statistical significance or user impact. Treat each manifest field as an untrusted claim until independently authenticated.

Inputs are capped at 4 MiB. Paths must be workspace-relative. Manifest and artifact paths reject symlinks. Report writes are exclusive, content-addressed, and verified by read-back. Secret-shaped fields and values, raw logs, prompts, bodies, content and chat text are rejected.

Report vulnerabilities privately through GitHub Security Advisories. Never attach production manifests, credentials, raw metrics, logs, or private business data.

