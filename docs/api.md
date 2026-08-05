# API outline

The API is rooted at `/api/v1`, returns JSON, and publishes OpenAPI. Collections use cursor pagination with allowlisted filters and sorts. Browser mutations require a secure session and CSRF token. Programmatic access uses hashed bearer tokens with explicit scopes.

Resource groups are `/auth`, `/devices`, `/agents`, `/ingest`, `/monitors`, `/alerts`, `/incidents`, `/vulnerabilities`, `/storage`, `/containers`, `/scans`, `/tokens`, `/events`, and `/health`.

Read-only scopes cover health, devices, alerts, incidents, vulnerabilities, services, metrics, storage, and containers. Administrative routes never accept read-only scopes. Errors contain a stable code, safe message, correlation ID, and optional field violations—never secrets or internal exception text.
