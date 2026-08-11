#!/bin/sh
set -eu

test "$(id -u)" -eq 0 || { echo "Run this updater with sudo" >&2; exit 1; }
test -f ./sentinel_agent.py || { echo "sentinel_agent.py is missing" >&2; exit 1; }
test -f ./sentinel_remediate.py || { echo "sentinel_remediate.py is missing" >&2; exit 1; }
test -f ./sentinel_containers.py || { echo "sentinel_containers.py is missing" >&2; exit 1; }

install -m 0755 ./sentinel_agent.py /usr/local/bin/sentinel-agent
install -d -o root -g root -m 0755 /usr/local/libexec
install -o root -g root -m 0755 ./sentinel_remediate.py /usr/local/libexec/sentinel-remediate
install -o root -g root -m 0755 ./sentinel_containers.py /usr/local/libexec/sentinel-containers
printf '%s\n' 'sentinel-agent ALL=(root) NOPASSWD: /usr/local/libexec/sentinel-remediate, /usr/local/libexec/sentinel-containers' >/etc/sudoers.d/sentinel-agent
chmod 0440 /etc/sudoers.d/sentinel-agent
command -v visudo >/dev/null && visudo -cf /etc/sudoers.d/sentinel-agent
install -d -o root -g root -m 0755 /etc/systemd/system/sentinel-agent.service.d
cat >/etc/systemd/system/sentinel-agent.service.d/executor.conf <<'EOF'
[Service]
NoNewPrivileges=false
ReadWritePaths=/var/lib/apt /var/cache/apt /etc/apt /usr /lib /bin /sbin
EOF
systemctl daemon-reload
systemctl restart sentinel-agent
systemctl status sentinel-agent --no-pager
