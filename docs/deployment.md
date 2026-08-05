# Deployment

Copy `.env.example` to `.env`, replace all `change-me` values, and deploy `docker-compose.yml`. Portainer Git stacks discover that conventional filename automatically. `compose.yml` is also retained for Docker Compose users who select it explicitly. Environment values belong in Portainer, not source control.

## Required Portainer variables

Before selecting **Deploy the stack**, add these environment variables in the Portainer stack editor:

- `POSTGRES_PASSWORD`: 64 random hexadecimal characters
- `SESSION_SECRET`: a different 64-character random hexadecimal value
- `DATA_ENCRYPTION_KEY`: another different 64-character random hexadecimal value

Generate each value on Linux with `openssl rand -hex 32`. Run it three times and do not reuse a value. Hexadecimal values avoid URL-escaping problems in the generated PostgreSQL connection URL. `DATABASE_URL` and `REDIS_URL` are constructed by the stack and should not be entered in Portainer.

Compose rejects missing values before creating containers. This prevents PostgreSQL from starting with a blank password and reporting only an indirect unhealthy-container error.

The API service uses Compose's `pull_policy: build`. Updating and redeploying the Git stack therefore rebuilds the local application image instead of silently reusing an older build. Portainer's image re-pull option applies to registry images and is not a substitute for rebuilding a Git build context.

The API binds to `127.0.0.1` by default. Set `BIND_ADDRESS` to a specific trusted LAN address only when intended. PostgreSQL and Redis publish no host ports. Liveness confirms the process; readiness checks dependencies and returns HTTP 503 when unavailable.

Before the first schema migration, backup consists of a PostgreSQL custom-format dump plus separately stored secrets. Redis is excluded. Tested scripts will ship with the first real migration. Reserve 2 CPU cores, 4 GB RAM, and at least 30 GB storage. Scanner phases will document separate peaks.
