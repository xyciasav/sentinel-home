# Agent protocol

An administrator creates a short-lived, single-use enrollment token. The agent generates its key locally, enrolls over HTTPS, and receives a device identity and certificate chain. Routine communication uses per-agent mTLS and individual revocation.

Every envelope carries protocol and agent versions, device and message IDs, monotonic sequence, collection and transmission times, payload type, compression, and checksum. The server validates identity, schema, size, clock skew, and replay state before acknowledgment.

Metrics batch briefly; important events send immediately. Inventory uses checksums and snapshots. A bounded encrypted local queue drops oldest high-frequency metrics before structured events. Signed heartbeat configuration can adjust allowlisted collectors and intervals. There is no arbitrary command message. The server supports the current and previous protocol major versions during upgrades.
