#!/bin/sh
set -eu

: "${SENTINEL_URL:?Set SENTINEL_URL}"
: "${SENTINEL_ENROLLMENT_TOKEN:?Set SENTINEL_ENROLLMENT_TOKEN}"

test "$(id -u)" -eq 0 || { echo "Run this installer with sudo" >&2; exit 1; }
command -v python3 >/dev/null || { echo "Python 3 is required" >&2; exit 1; }

id sentinel-agent >/dev/null 2>&1 || useradd --system --home-dir /var/lib/sentinel-agent --shell /usr/sbin/nologin sentinel-agent
install -d -o sentinel-agent -g sentinel-agent -m 0700 /var/lib/sentinel-agent
install -m 0755 ./sentinel_agent.py /usr/local/bin/sentinel-agent

allow_http="${SENTINEL_ALLOW_HTTP:-false}"
runuser -u sentinel-agent -- env SENTINEL_URL="$SENTINEL_URL" SENTINEL_ENROLLMENT_TOKEN="$SENTINEL_ENROLLMENT_TOKEN" SENTINEL_ALLOW_HTTP="$allow_http" /usr/local/bin/sentinel-agent --state /var/lib/sentinel-agent/token --enroll-only

cat >/etc/sentinel-agent.env <<EOF
SENTINEL_URL=$SENTINEL_URL
SENTINEL_ALLOW_HTTP=$allow_http
SENTINEL_AGENT_STATE=/var/lib/sentinel-agent/token
EOF
chmod 0644 /etc/sentinel-agent.env
cat >/etc/systemd/system/sentinel-agent.service <<'EOF'
[Unit]
Description=Sentinel Home Linux Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sentinel-agent
Group=sentinel-agent
EnvironmentFile=/etc/sentinel-agent.env
ExecStart=/usr/local/bin/sentinel-agent
Restart=always
RestartSec=10
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/sentinel-agent

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now sentinel-agent
echo "Sentinel agent installed and started."
