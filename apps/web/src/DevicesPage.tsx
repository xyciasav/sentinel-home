import { FormEvent, ReactNode, useState } from "react";
import { api, Device, DuplicateCandidate, HostOverview } from "./api";

export function DevicesPage({
  devices,
  csrf,
  refresh,
}: {
  devices: Device[];
  csrf: string;
  refresh: () => Promise<void>;
}) {
  const [adding, setAdding] = useState(false),
    [editing, setEditing] = useState<Device | null>(null),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [reviewing, setReviewing] = useState(false),
    [candidates, setCandidates] = useState<DuplicateCandidate[]>([]),
    [overview, setOverview] = useState<HostOverview | null>(null);
  const close = () => {
    setAdding(false);
    setEditing(null);
    setError("");
  };
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    const data = new FormData(event.currentTarget);
    const payload = {
      display_name: data.get("name"),
      agent_applicable: data.get("agent_applicable") === "on",
      address: data.get("address"),
      hostname: data.get("hostname") || null,
      device_type: data.get("type") || null,
      criticality: data.get("criticality"),
      trust: data.get("trust"),
      monitor_port: Number(data.get("port")),
      notes: data.get("notes") || null,
    };
    try {
      editing
        ? await api.updateDevice(editing.id, payload, csrf)
        : await api.createDevice(payload, csrf);
      close();
      await refresh();
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Could not save device",
      );
    } finally {
      setBusy(false);
    }
  }
  async function review() {
    setBusy(true);
    try {
      setCandidates(await api.duplicateDevices());
      setReviewing(true);
    } finally {
      setBusy(false);
    }
  }
  async function merge(target: Device, source: Device) {
    if (confirm(`Merge ${source.display_name} into ${target.display_name}?`)) {
      await api.mergeDevice(target.id, source.id, csrf);
      setCandidates(await api.duplicateDevices());
      await refresh();
    }
  }
  async function mute(device: Device) {
    await api.toggleDeviceNotifications(
      device.id,
      !device.notifications_muted,
      csrf,
    );
    await refresh();
  }
  async function view(device: Device) {
    setBusy(true);
    try {
      setOverview(await api.deviceOverview(device.id));
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Could not load host overview",
      );
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <header>
        <div>
          <p className="eyebrow">INVENTORY</p>
          <h1>Devices</h1>
          <p>
            Servers, appliances, printers, routers, and everything else on your
            network.
          </p>
        </div>
        <div className="row-actions">
          <button onClick={() => void review()}>Review duplicates</button>
          <button className="primary compact" onClick={() => setAdding(true)}>
            + Add device
          </button>
        </div>
      </header>
      {(adding || editing) && (
        <div className="modal-backdrop">
          <form className="device-form panel" onSubmit={submit}>
            <div className="panel-title">
              <div>
                <p className="eyebrow">
                  {editing ? "EDIT DEVICE" : "NEW DEVICE"}
                </p>
                <h2>{editing ? "Update device" : "Start monitoring"}</h2>
              </div>
              <button type="button" className="close" onClick={close}>
                ×
              </button>
            </div>
            <label>
              Display name
              <input
                name="name"
                required
                defaultValue={editing?.display_name}
              />
            </label>
            <label>
              IP address or local hostname
              <input name="address" required defaultValue={editing?.address} />
            </label>
            <label>
              Hostname (optional)
              <input name="hostname" defaultValue={editing?.hostname ?? ""} />
            </label>
            <div className="form-row">
              <label>
                Device type
                <select
                  name="type"
                  defaultValue={editing?.device_type ?? "server"}
                >
                  <option value="server">Server</option>
                  <option value="workstation">Workstation</option>
                  <option value="raspberry-pi">Raspberry Pi</option>
                  <option value="home-assistant">Home Assistant</option>
                  <option value="printer">Printer</option>
                  <option value="router">Router / network appliance</option>
                  <option value="iot">IoT / appliance</option>
                </select>
              </label>
              <label>
                TCP port
                <input
                  name="port"
                  type="number"
                  min="1"
                  max="65535"
                  defaultValue={editing?.monitor_port ?? 443}
                  required
                />
              </label>
            </div>
            <div className="form-row">
              <label>
                Criticality
                <select
                  name="criticality"
                  defaultValue={editing?.criticality ?? "normal"}
                >
                  <option value="low">Low</option>
                  <option value="normal">Normal</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
              </label>
              <label>
                Trust
                <select name="trust" defaultValue={editing?.trust ?? "trusted"}>
                  <option value="trusted">Trusted</option>
                  <option value="unknown">Unknown</option>
                  <option value="guest">Guest</option>
                  <option value="ignored">Ignored</option>
                </select>
              </label>
            </div>
            <label className="check-label appliance-setting">
              <input
                name="agent_applicable"
                type="checkbox"
                defaultChecked={editing?.agent_applicable ?? true}
              />{" "}
              This device can run the Sentinel Linux agent
            </label>
            <p className="quiet appliance-help">
              Turn this off for printers, routers, TVs, Home Assistant OS, and
              locked-down appliances. Availability and network monitoring
              continue normally.
            </p>
            <label>
              Notes
              <textarea
                name="notes"
                rows={3}
                defaultValue={editing?.notes ?? ""}
              />
            </label>
            {error && <div className="error">{error}</div>}
            <div className="form-actions">
              <button type="button" onClick={close}>
                Cancel
              </button>
              <button className="primary compact" disabled={busy}>
                {busy ? "Saving…" : "Save and check"}
              </button>
            </div>
          </form>
        </div>
      )}
      {error && !adding && !editing && (
        <div className="error storage-error">{error}</div>
      )}
      {devices.length === 0 ? (
        <div className="empty-state panel">
          <h2>No devices yet</h2>
        </div>
      ) : (
        <div className="device-list panel">
          <div className="device-row heading">
            <span>Device</span>
            <span>Target</span>
            <span>Status</span>
            <span>Latency</span>
            <span />
          </div>
          {devices.map((device) => (
            <div className="device-row" key={device.id}>
              <span>
                <b>{device.display_name}</b>
                <small>
                  {device.device_type ?? "Device"} ·{" "}
                  {device.agent_applicable
                    ? "Agent eligible"
                    : "Appliance · no agent expected"}
                </small>
              </span>
              <span>
                {device.address}:{device.monitor_port}
              </span>
              <span>
                <i className={`status-dot ${device.status}`} />
                {device.status}
              </span>
              <span>
                {device.last_latency_ms ? `${device.last_latency_ms} ms` : "—"}
              </span>
              <div className="row-actions">
                <button
                  className={`mute-toggle ${device.notifications_muted ? "muted" : ""}`}
                  onClick={() => void mute(device)}
                >
                  {device.notifications_muted ? "Muted" : "Alerts"}
                </button>
                <button onClick={() => void view(device)}>View host</button>
                <button onClick={() => setEditing(device)}>Edit</button>
                <button
                  onClick={async () => {
                    await api.checkDevice(device.id, csrf);
                    await refresh();
                  }}
                >
                  Check
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
      {overview && (
        <HostOverviewModal
          overview={overview}
          close={() => setOverview(null)}
        />
      )}
      {reviewing && (
        <div className="modal-backdrop">
          <div className="panel duplicate-modal">
            <div className="panel-title">
              <h2>Possible duplicate devices</h2>
              <button className="close" onClick={() => setReviewing(false)}>
                ×
              </button>
            </div>
            {candidates.length === 0 ? (
              <div className="empty-state">
                <h2>No likely duplicates</h2>
              </div>
            ) : (
              <div className="duplicate-list">
                {candidates.map((item) => (
                  <article key={`${item.left.id}-${item.right.id}`}>
                    <div className="duplicate-confidence">
                      <b>{item.confidence}%</b>
                      <small>match</small>
                    </div>
                    <div>
                      <b>{item.left.display_name}</b>
                      <small>{item.left.address}</small>
                    </div>
                    <span>⇄</span>
                    <div>
                      <b>{item.right.display_name}</b>
                      <small>{item.right.address}</small>
                    </div>
                    <div className="duplicate-reasons">
                      {item.reasons.map((x) => (
                        <i key={x}>{x}</i>
                      ))}
                    </div>
                    <div className="row-actions">
                      <button onClick={() => void merge(item.left, item.right)}>
                        Keep {item.left.display_name}
                      </button>
                      <button onClick={() => void merge(item.right, item.left)}>
                        Keep {item.right.display_name}
                      </button>
                    </div>
                  </article>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
}

function HostOverviewModal({
  overview,
  close,
}: {
  overview: HostOverview;
  close: () => void;
}) {
  const agent = overview.agent;
  return (
    <div className="modal-backdrop" onMouseDown={close}>
      <div
        className="panel host-overview"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <div className="panel-title">
          <div>
            <p className="eyebrow">UNIFIED HOST</p>
            <h2>{overview.device.display_name}</h2>
            <p>
              {overview.device.address} ·{" "}
              {overview.device.device_type || "device"} ·{" "}
              {overview.device.criticality} criticality
            </p>
          </div>
          <button className="close" onClick={close}>
            ×
          </button>
        </div>
        <section className="host-score-grid">
          <HostMetric label="Availability" value={overview.device.status} />
          <HostMetric
            label="Agent"
            value={
              !overview.device.agent_applicable
                ? "Not applicable"
                : agent?.connected
                  ? "Connected"
                  : "Offline"
            }
          />
          <HostMetric
            label="Actionable risk"
            value={String(overview.actionable_vulnerabilities)}
            danger={overview.actionable_vulnerabilities > 0}
          />
          <HostMetric
            label="Known exploited"
            value={String(overview.known_exploited)}
            danger={overview.known_exploited > 0}
          />
        </section>
        {agent && (
          <section>
            <h3>System health</h3>
            <div className="host-score-grid">
              <HostMetric
                label="CPU"
                value={`${agent.cpu_percent ?? "—"}%`}
                danger={(agent.cpu_percent ?? 0) >= 85}
              />
              <HostMetric
                label="Memory"
                value={`${agent.memory_percent ?? "—"}%`}
                danger={(agent.memory_percent ?? 0) >= 85}
              />
              <HostMetric
                label="Disk"
                value={`${agent.disk_percent ?? "—"}%`}
                danger={(agent.disk_percent ?? 0) >= 90}
              />
              <HostMetric label="Security scan" value={agent.scan_status} />
            </div>
            <p className="quiet">
              Last scan:{" "}
              {agent.last_scan_at
                ? new Date(agent.last_scan_at).toLocaleString()
                : "not yet"}{" "}
              · Next:{" "}
              {agent.next_scan_at
                ? new Date(agent.next_scan_at).toLocaleString()
                : "not scheduled"}{" "}
              · {overview.informational_vulnerabilities} informational findings
            </p>
            {agent.scan_error && (
              <div className="error">{agent.scan_error}</div>
            )}
          </section>
        )}
        <div className="host-columns">
          <HostList title={`Services (${overview.services.length})`}>
            {overview.services.map((item) => (
              <div key={item.id}>
                <i className={`status-dot ${item.status}`} />
                <span>
                  <b>{item.name}</b>
                  <small>{item.url}</small>
                </span>
                <em>
                  {item.response_ms ? `${item.response_ms} ms` : item.status}
                </em>
              </div>
            ))}
          </HostList>
          <HostList title={`Containers (${overview.containers.length})`}>
            {overview.containers.map((item) => (
              <div key={item.id}>
                <i
                  className={`status-dot ${item.state === "running" && item.health !== "unhealthy" ? "up" : "down"}`}
                />
                <span>
                  <b>{item.name}</b>
                  <small>{item.image}</small>
                </span>
                <em>
                  {item.state}
                  {item.health ? ` · ${item.health}` : ""}
                </em>
              </div>
            ))}
          </HostList>
        </div>
        <HostList title="Recent network changes">
          {overview.recent_changes.map((item, index) => (
            <div key={`${item.detected_at}-${index}`}>
              <i className="status-dot paused" />
              <span>
                <b>{item.kind.replaceAll("_", " ")}</b>
                <small>
                  Port {item.port}
                  {item.service ? ` · ${item.service}` : ""}
                </small>
              </span>
              <em>{new Date(item.detected_at).toLocaleString()}</em>
            </div>
          ))}
        </HostList>
      </div>
    </div>
  );
}

function HostMetric({
  label,
  value,
  danger,
}: {
  label: string;
  value: string;
  danger?: boolean;
}) {
  return (
    <div>
      <small>{label}</small>
      <b className={danger ? "report-danger" : ""}>{value}</b>
    </div>
  );
}

function HostList({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="host-list">
      <h3>{title}</h3>
      {children || <p className="quiet">No linked data.</p>}
    </section>
  );
}
