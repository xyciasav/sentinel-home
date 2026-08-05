# Data model

Durable records use UUIDv7 identifiers and UTC timestamps. Bounded JSONB holds source evidence; searchable values remain typed columns.

Aggregate roots cover identity (`users`, `roles`, `sessions`, `api_tokens`, `agent_credentials`, `audit_events`); devices and inventory (`devices`, addresses, identifiers, tags, agents, ports, services, software, packages, snapshots, changes); monitoring (`monitors`, results, metric samples and rollups, system events, maintenance windows); response (`alerts`, occurrences, silences, incidents, timeline events, hypotheses, notifications); vulnerabilities (advisories, aliases, findings, evidence, status history, scans); and storage/Docker (roots, metadata, snapshots, findings, protection rules, containers, images, volumes).

An IP address is an observation, never a device identity. Reconciliation uses agent identity, stable OS identifiers, MAC history, hostname, and observation context. Ambiguity creates a review candidate instead of silently merging devices.

Five-second metrics retain full resolution for 72 hours and five-minute rollups for 30 days. Events and histories default to 30 days. Inventory persists until manual deletion. Retention uses small partitions or key ranges and emits an audit summary.
