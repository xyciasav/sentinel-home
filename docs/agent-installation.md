# Linux agent installation

The Linux agent reports CPU, memory, root-filesystem capacity, uptime, and installed DEB/RPM packages. It does not accept commands or read file contents.

Python 3.8 or newer and systemd are required on the monitored host.

## Install

1. Add the Linux host to **Devices** in Sentinel.
2. Open **Agents**, select the device, and generate a one-time install command.
3. Review `sentinel_agent.py` and `install.sh`, then run the displayed command on that host.
4. Confirm that the agent becomes **Connected** within 30 seconds.

The enrollment token expires after 30 minutes and can only be used once. The resulting agent credential is stored at `/var/lib/sentinel-agent/token`, readable only by the dedicated `sentinel-agent` account. The server stores only its SHA-256 hash.

The service runs without root privileges. Its systemd unit enables `NoNewPrivileges`, a read-only system filesystem, a private temporary directory, and a single writable state directory.

## HTTP versus HTTPS

HTTPS is required by default. The generated command sets `SENTINEL_ALLOW_HTTP=true` only when the dashboard itself is being accessed over plain HTTP. Use this only on a trusted private LAN; bearer credentials can be exposed to an on-path observer over HTTP.

## Operations

```sh
systemctl status sentinel-agent
journalctl -u sentinel-agent -n 100
systemctl restart sentinel-agent
```

To uninstall, stop and disable the service, then remove the unit, executable, environment file, state directory, and `sentinel-agent` system user. Removing an agent from the server UI will be added with credential revocation in a later increment.
