#!/bin/sh
set -eu

: "${SENTINEL_URL:?Set SENTINEL_URL}"
: "${SENTINEL_ENROLLMENT_TOKEN:?Set SENTINEL_ENROLLMENT_TOKEN}"

test "$(id -u)" -eq 0 || { echo "Run this installer with sudo" >&2; exit 1; }
command -v python3 >/dev/null || { echo "Python 3 is required" >&2; exit 1; }
python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)' || { echo "Python 3.8 or newer is required" >&2; exit 1; }

id sentinel-agent >/dev/null 2>&1 || useradd --system --home-dir /var/lib/sentinel-agent --shell /usr/sbin/nologin sentinel-agent
install -d -o sentinel-agent -g sentinel-agent -m 0700 /var/lib/sentinel-agent
install -m 0755 ./sentinel_agent.py /usr/local/bin/sentinel-agent
install -d -o root -g root -m 0755 /usr/local/libexec
install -o root -g root -m 0755 ./sentinel_remediate.py /usr/local/libexec/sentinel-remediate
install -o root -g root -m 0755 ./sentinel_containers.py /usr/local/libexec/sentinel-containers
printf '%s\n' 'sentinel-agent ALL=(root) NOPASSWD: /usr/local/libexec/sentinel-remediate, /usr/local/libexec/sentinel-containers' >/etc/sudoers.d/sentinel-agent
chmod 0440 /etc/sudoers.d/sentinel-agent
command -v visudo >/dev/null && visudo -cf /etc/sudoers.d/sentinel-agent

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
NoNewPrivileges=false
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/sentinel-agent /var/lib/apt /var/lib/dpkg /var/cache/apt /var/log/apt /etc/apt /usr /lib /bin /sbin

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now sentinel-agent
printf 'Installed agent: '
/usr/local/bin/sentinel-agent --version
printf 'Installed executor: '
/usr/local/libexec/sentinel-remediate --version
echo "Sentinel agent installed and started."
