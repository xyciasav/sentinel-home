# Deployment

Copy `.env.example` to `.env`, replace all `change-me` values, and deploy `compose.yml`. Portainer Git stacks can reference the repository and Compose path directly; environment values belong in Portainer, not source control.

The API binds to `127.0.0.1` by default. Set `BIND_ADDRESS` to a specific trusted LAN address only when intended. PostgreSQL and Redis publish no host ports. Liveness confirms the process; readiness checks dependencies and returns HTTP 503 when unavailable.

Before the first schema migration, backup consists of a PostgreSQL custom-format dump plus separately stored secrets. Redis is excluded. Tested scripts will ship with the first real migration. Reserve 2 CPU cores, 4 GB RAM, and at least 30 GB storage. Scanner phases will document separate peaks.
