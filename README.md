# Sentinel Home

Sentinel Home is a self-hosted home-network observability and security platform. This repository currently contains the Phase 1 architecture contracts and a minimal runnable API foundation. It intentionally does not scan, modify, restart, update, or delete anything.

## Current capabilities

- FastAPI service with liveness, readiness, and version endpoints
- Environment-based, fail-closed production configuration
- PostgreSQL and Redis connectivity readiness checks
- Phase 1 architecture, threat model, data model, API, and agent protocol documents
- Production-oriented and development Docker Compose stacks
- Unit tests for health behavior and configuration safety
- Versioned PostgreSQL migrations and the initial identity/device inventory schema
- Database-backed setup status at `/api/v1/setup/status`
- One-time administrator bootstrap and Argon2id authentication
- Hashed server-side sessions, CSRF-protected logout, and authentication audit events
- Responsive first-run, login, and overview web interface
- Authenticated device inventory with safe private-network TCP monitoring every 30 seconds
- Read-only storage metadata scans with large/stale file recommendations and protected paths
- Real-data reports for service uptime, response times, incidents, vulnerabilities, network changes, and storage findings
- Persistent background storage jobs and a prioritized Linux remediation Action Center

## Quick start

1. Copy `.env.example` to `.env` and replace every value marked `change-me`.
2. Run `docker compose up --build`. Docker and Portainer discover `docker-compose.yml` automatically.
3. Open `http://127.0.0.1:8080/api/v1/health/ready`.

For Portainer, set `POSTGRES_PASSWORD`, `SESSION_SECRET`, and `DATA_ENCRYPTION_KEY` in the stack environment before deployment. Generate each separately with `openssl rand -hex 32`. See the [deployment guide](docs/deployment.md).

To scan a folder on the Docker host, set `STORAGE_SCAN_PATH` to its absolute host path before deploying. Sentinel mounts it read-only at `/scan`; targets entered in the UI are relative to that mount. Keep the default `./storage-scan` if storage analysis is not needed yet.

Do not mount the Docker host's filesystem root. Mount only the folders you intend Sentinel to inventory. For storage on another device, first mount that SMB/NFS share on the Docker host, then use that local mount point as `STORAGE_SCAN_PATH`; Sentinel does not accept a remote IP or share URL directly.

The default Compose binding is loopback-only. To make the service available on a trusted LAN, explicitly set `BIND_ADDRESS` to the server's LAN address.

Opening the server's root URL loads the Sentinel web interface. Interactive API documentation remains available at `/docs`.

## Initialize the administrator

After deployment, open `/docs`, expand `POST /api/v1/auth/bootstrap`, select **Try it out**, and submit a username plus a password of at least 12 characters. Bootstrap succeeds only while no administrator exists and logs you in with an HttpOnly session cookie. Store the returned CSRF token for state-changing API requests during that session.

Use `POST /api/v1/auth/login` for later sessions, `GET /api/v1/auth/me` to verify the current identity, and send the CSRF value in the `X-CSRF-Token` header when calling `POST /api/v1/auth/logout`.

## Local development

Requires Python 3.12 or newer.

```powershell
python -m venv .venv
.venv\Scripts\pip install -e ".[dev]"
.venv\Scripts\pytest
.venv\Scripts\uvicorn sentinel.main:app --reload
```

## Documentation

- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Data model](docs/data-model.md)
- [API outline](docs/api.md)
- [Agent protocol](docs/agent-protocol.md)
- [Roadmap](docs/roadmap.md)
- [Deployment](docs/deployment.md)

This phase is observation-only. There are no remediation endpoints, remote command execution facilities, or active scanners.
