# Architecture

Sentinel Home is a modular monolith with independently runnable API, worker, and scheduler roles sharing one Python package and database schema. This avoids microservice overhead while retaining clear module boundaries. Browser and external dashboards use the same versioned REST API; server-sent events will provide live updates.

## Trust boundaries

1. Browsers and API clients are untrusted until authenticated and authorized.
2. Agents possess per-device identities, but their payloads remain untrusted input.
3. Scanner processes and all scanner output are untrusted.
4. PostgreSQL is the durable system of record; Redis contains replaceable coordination state only.
5. Privileged host collection stays inside endpoint agents. The API never receives a Docker socket or remote shell.

## Modules

- Identity: users, sessions, roles, API tokens, enrollment, and audit events.
- Inventory: devices, addresses, agents, ports, services, software, and changes.
- Telemetry: metrics, structured events, rollups, and retention.
- Availability: monitors, results, dependencies, and maintenance windows.
- Response: alerts, incidents, timelines, evidence, and notifications.
- Vulnerabilities: advisories, findings, normalization, and scan evidence.
- Storage: metadata snapshots, growth findings, protection rules, and recommendations.
- Integrations: scanners, Docker, vulnerability sources, and Resend.

Modules communicate through explicit services and durable domain events, not another module's persistence internals. Ingestion validates size, schema, identity, timestamps, and idempotency before committing an observation and outbox event together. Workers use those events to update state, evaluate alerts, and build incident timelines.

## Decisions

- PostgreSQL partitioning and rollups precede any TimescaleDB adoption.
- SSE precedes WebSockets because traffic is predominantly server-to-client.
- Go agents provide small cross-platform service binaries.
- No remediation or arbitrary command channel exists in initial releases.
- Active scanners receive separate capability and concurrency policies.
