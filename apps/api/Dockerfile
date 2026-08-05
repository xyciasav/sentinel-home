FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH="/opt/venv/bin:$PATH"
RUN python -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir --upgrade pip
WORKDIR /app
COPY pyproject.toml README.md ./
COPY apps/api/src ./apps/api/src
COPY alembic.ini ./
COPY database/migrations ./database/migrations
RUN pip install --no-cache-dir .
RUN addgroup --system --gid 10001 sentinel && adduser --system --uid 10001 --ingroup sentinel --home /nonexistent --no-create-home sentinel
USER 10001:10001
EXPOSE 8080
CMD ["uvicorn", "sentinel.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
