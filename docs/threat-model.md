# Threat model

Protected assets include device inventory, topology, filenames, logs, findings, credentials, agent identities, API tokens, encryption keys, and service availability.

## Principal threats and controls

- Credential theft: Argon2id password hashing, hashed API tokens, secure cookies, session rotation, expiry, and secret redaction.
- Rogue enrollment: single-use short-lived tokens followed by per-agent mTLS credentials and revocation.
- Forged or replayed telemetry: agent identity, sequence numbers, unique event IDs, bounded clock skew, and idempotency.
- Parser and command injection: no shell interpolation, strict schemas, subprocess time/output limits, and scanner sandboxing.
- SSRF through monitors: target policy, DNS revalidation, redirect limits, metadata-address blocks, and subnet allowlists.
- Scanner disruption: safe profiles, exclusions, rate/concurrency limits, scan windows, and audit records.
- Privilege escalation: non-root containers, dropped capabilities, read-only filesystems, and collector-specific permissions.
- Data exfiltration: LAN-only binding, encrypted transport, local vulnerability matching, scoped tokens, and least-data collection.
- Storage exhaustion: partition retention, bounded logs/artifacts, forecasts, and emergency ingestion throttling.
- Misleading diagnoses: immutable evidence links, confidence levels, contradictory evidence, and explicit unknown cause.

## Security invariants

- Read-only tokens cannot reach administrative routes.
- Raw passwords, API tokens, enrollment tokens, and agent private keys are never stored.
- No endpoint accepts arbitrary commands for agent execution.
- No finding triggers deletion, restart, update, isolation, or blocking.
- Scanner output is never trusted as HTML or as an identifier without normalization.

The model is reviewed before enabling every privileged collector.
