# Sentinel Home

Sentinel Home is a self-hosted home-network observability and security platform. This repository currently contains the Phase 1 architecture contracts and a minimal runnable API foundation. It intentionally does not scan, modify, restart, update, or delete anything.

## Current capabilities

- FastAPI service with liveness, readiness, and version endpoints
- Environment-based, fail-closed production configuration
- PostgreSQL and Redis connectivity readiness checks
- Phase 1 architecture, threat model, data model, API, and agent protocol documents
- Production-oriented and development Docker Compose stacks
- Unit tests for health behavior and configuration safety

## Quick start

1. Copy `.env.example` to `.env` and replace every value marked `change-me`.
2. Run `docker compose up --build`. Docker and Portainer discover `docker-compose.yml` automatically.
3. Open `http://127.0.0.1:8080/api/v1/health/ready`.

For Portainer, set `POSTGRES_PASSWORD`, `SESSION_SECRET`, and `DATA_ENCRYPTION_KEY` in the stack environment before deployment. Generate each separately with `openssl rand -hex 32`. See the [deployment guide](docs/deployment.md).

The default Compose binding is loopback-only. To make the service available on a trusted LAN, explicitly set `BIND_ADDRESS` to the server's LAN address.

Opening the server's root URL redirects to the interactive API documentation at `/docs`. A full dashboard is scheduled for Phase 2 and is not part of this foundation release.

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
