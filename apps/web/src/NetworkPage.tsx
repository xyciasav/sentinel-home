import { useEffect, useMemo, useState } from "react";
import {
  api,
  DiscoveredHost,
  DiscoveryRun,
  InventorySource,
  NetworkAsset,
  NetworkChange,
  NetworkIdentityEvent,
  PiHoleTraffic,
} from "./api";
import { DiscoveryPage } from "./DiscoveryPage";
import { NetworkChangesPage } from "./NetworkChangesPage";
import { SourcesPage } from "./SourcesPage";

export function NetworkPage({
  sources,
  run,
  changes,
  csrf,
  refreshSources,
  refreshDiscovery,
  refreshDevices,
  updateHost,
}: {
  sources: InventorySource[];
  run: DiscoveryRun | null;
  changes: NetworkChange[];
  csrf: string;
  refreshSources: () => Promise<void>;
  refreshDiscovery: () => Promise<void>;
  refreshDevices: () => Promise<void>;
  updateHost: (host: DiscoveredHost) => void;
}) {
  const [section, setSection] = useState<
    | "overview"
    | "topology"
    | "traffic"
    | "inventory"
    | "alerts"
    | "discovery"
    | "changes"
  >("overview");
  const [assets, setAssets] = useState<NetworkAsset[]>([]),
    [activity, setActivity] = useState<NetworkIdentityEvent[]>([]),
    [loading, setLoading] = useState(true);
  async function loadAssets() {
    setLoading(true);
    try {
      setAssets(await api.networkInventory());
    } finally {
      setLoading(false);
    }
  }
  async function loadActivity() {
    setActivity(await api.networkActivity());
  }
  useEffect(() => {
    void loadAssets();
    void loadActivity();
  }, []);
  const tabs: [typeof section, string][] = [
    ["overview", "Overview"],
    ["topology", "Topology"],
    ["traffic", "DNS traffic"],
    ["inventory", "Connected inventory"],
    [
      "alerts",
      `Alerts${activity.filter((x) => !x.acknowledged_at).length ? ` (${activity.filter((x) => !x.acknowledged_at).length})` : ""}`,
    ],
    ["discovery", "Discovery"],
    ["changes", "Port changes"],
  ];
  return (
    <>
      <div className="network-tabs panel">
        {tabs.map(([key, label]) => (
          <button
            key={key}
            className={section === key ? "active" : ""}
            onClick={() => {
              setSection(key);
              if (key === "overview" || key === "topology") void loadAssets();
              if (key === "alerts") void loadActivity();
            }}
          >
            {label}
          </button>
        ))}
      </div>
      {section === "overview" ? (
        <NetworkOverview
          assets={assets}
          loading={loading}
          csrf={csrf}
          refresh={async () => {
            await loadAssets();
            await refreshDevices();
          }}
        />
      ) : section === "topology" ? (
        <NetworkTopology assets={assets} />
      ) : section === "traffic" ? (
        <DnsTraffic
          sources={sources}
          csrf={csrf}
          refreshSources={refreshSources}
        />
      ) : section === "inventory" ? (
        <SourcesPage
          sources={sources}
          csrf={csrf}
          refresh={async () => {
            await refreshSources();
            await loadAssets();
          }}
          refreshDevices={refreshDevices}
        />
      ) : section === "alerts" ? (
        <NetworkAlerts events={activity} csrf={csrf} refresh={loadActivity} />
      ) : section === "discovery" ? (
        <DiscoveryPage
          run={run}
          csrf={csrf}
          refresh={refreshDiscovery}
          refreshDevices={refreshDevices}
          updateHost={updateHost}
        />
      ) : (
        <NetworkChangesPage changes={changes} />
      )}
    </>
  );
}

function DnsTraffic({
  sources,
  csrf,
  refreshSources,
}: {
  sources: InventorySource[];
  csrf: string;
  refreshSources: () => Promise<void>;
}) {
  const [items, setItems] = useState<PiHoleTraffic[]>([]),
    [loading, setLoading] = useState(true),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  async function load() {
    setLoading(true);
    setError("");
    try {
      setItems(await api.piholeTraffic());
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Could not load DNS traffic",
      );
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => {
    void load();
  }, []);
  async function analyze() {
    setBusy(true);
    setError("");
    try {
      for (const source of sources.filter((x) => x.kind === "pihole"))
        await api.syncSource(source.id, csrf);
      await Promise.all([load(), refreshSources()]);
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Traffic analysis failed",
      );
    } finally {
      setBusy(false);
    }
  }
  const total = items.reduce((sum, item) => sum + (item.queries.total || 0), 0),
    blocked = items.reduce((sum, item) => sum + (item.queries.blocked || 0), 0),
    anomalies = items.flatMap((item) =>
      item.anomalies.map((alert) => ({ ...alert, source: item.source_name })),
    );
  return (
    <>
      <header>
        <div>
          <p className="eyebrow">PI-HOLE TRAFFIC INTELLIGENCE</p>
          <h1>DNS traffic</h1>
          <p>
            See which clients and domains are busiest, with unusual changes
            compared against your own network baseline.
          </p>
        </div>
        <button
          className="primary compact"
          disabled={busy || !sources.some((x) => x.kind === "pihole")}
          onClick={() => void analyze()}
        >
          {busy ? "Analyzing…" : "Analyze now"}
        </button>
      </header>
      {error && <div className="error">{error}</div>}
      {!sources.some((x) => x.kind === "pihole") ? (
        <div className="empty-state panel">
          <h2>Connect Pi-hole to analyze DNS traffic</h2>
          <p>
            Add it under Connected inventory using its API key or application
            password.
          </p>
        </div>
      ) : loading ? (
        <div className="empty-state panel">
          <h2>Loading traffic…</h2>
        </div>
      ) : (
        <>
          <section className="status-grid">
            <article className="status-card">
              <p>DNS queries</p>
              <strong>{total.toLocaleString()}</strong>
              <small>Current Pi-hole reporting period</small>
            </article>
            <article className="status-card">
              <p>Blocked</p>
              <strong>{blocked.toLocaleString()}</strong>
              <small>
                {total
                  ? `${((blocked / total) * 100).toFixed(1)}% of queries`
                  : "No query data"}
              </small>
            </article>
            <article className="status-card">
              <p>Unusual activity</p>
              <strong>{anomalies.length}</strong>
              <small>
                {anomalies.length
                  ? "Review detected deviations"
                  : "No current deviations"}
              </small>
            </article>
            <article className="status-card">
              <p>Baseline</p>
              <strong>
                {Math.max(0, ...items.map((x) => x.baseline_samples))}
              </strong>
              <small>Traffic samples learned</small>
            </article>
          </section>
          {anomalies.length > 0 && (
            <section className="panel dns-anomalies">
              <div className="panel-title">
                <div>
                  <p className="eyebrow">NEEDS ATTENTION</p>
                  <h2>Unusual traffic</h2>
                </div>
              </div>
              {anomalies.map((item, index) => (
                <article key={`${item.kind}-${index}`}>
                  <i className={`alert-severity ${item.severity}`} />
                  <div>
                    <b>{item.message}</b>
                    <small>
                      {item.source} · Compared with your recent Pi-hole baseline
                    </small>
                  </div>
                </article>
              ))}
            </section>
          )}
          <div className="dns-source-grid">
            {items.map((item) => (
              <article className="panel dns-source" key={item.source_id}>
                <div className="panel-title">
                  <div>
                    <p className="eyebrow">{item.status.toUpperCase()}</p>
                    <h2>{item.source_name}</h2>
                    <span className="tag">
                      Pi-hole API: {item.api_mode} · {item.data_source}
                    </span>
                    <small>
                      {item.collected_at
                        ? `Analyzed ${new Date(item.collected_at).toLocaleString()}`
                        : "Waiting for first sync"}
                    </small>
                  </div>
                </div>
                {item.diagnostics.map((message) => (
                  <div className="traffic-diagnostic" key={message}>
                    <b>Why no data?</b>
                    <span>{message}</span>
                  </div>
                ))}
                <TrafficList
                  title="Busiest clients"
                  items={item.top_clients.map((x) => ({
                    name: x.client,
                    count: x.count,
                  }))}
                />
                <TrafficList
                  title="Top permitted domains"
                  items={item.top_domains.map((x) => ({
                    name: x.domain,
                    count: x.count,
                  }))}
                />
                <TrafficList
                  title="Top blocked domains"
                  items={item.top_blocked_domains.map((x) => ({
                    name: x.domain,
                    count: x.count,
                  }))}
                />
              </article>
            ))}
          </div>
          <p className="quiet dns-privacy">
            Sentinel stores aggregate rankings and anomaly scores, not DNS
            payloads or complete query history. A baseline normally needs four
            successful syncs before volume alerts activate.
          </p>
        </>
      )}
    </>
  );
}

function TrafficList({
  title,
  items,
}: {
  title: string;
  items: { name: string; count: number }[];
}) {
  const max = Math.max(1, ...items.map((x) => x.count));
  return (
    <section className="traffic-list">
      <h3>{title}</h3>
      {items.length === 0 ? (
        <div className="traffic-empty">
          <p>No ranking data returned.</p>
          <small>See the diagnostic at the top of this Pi-hole card.</small>
        </div>
      ) : (
        items.slice(0, 10).map((item) => (
          <div key={item.name}>
            <span>
              <b>{item.name}</b>
              <small>{item.count.toLocaleString()}</small>
            </span>
            <i>
              <em
                style={{ width: `${Math.max(2, (item.count / max) * 100)}%` }}
              />
            </i>
          </div>
        ))
      )}
    </section>
  );
}

function subnet(address: string | null) {
  if (!address) return "Identity only";
  const parts = address.split(".");
  return parts.length === 4
    ? `${parts.slice(0, 3).join(".")}.0/24`
    : "Other addresses";
}
function NetworkTopology({ assets }: { assets: NetworkAsset[] }) {
  const groups = useMemo(() => {
    const result: Record<string, NetworkAsset[]> = {};
    for (const asset of assets)
      (result[subnet(asset.address)] ??= []).push(asset);
    return result;
  }, [assets]);
  return (
    <>
      <header>
        <div>
          <p className="eyebrow">NETWORK MAP</p>
          <h1>Topology</h1>
          <p>
            Assets grouped by observed network segment, with their identity
            sources and current state.
          </p>
        </div>
      </header>
      <div className="topology-map">
        <article className="topology-core panel">
          <span>SH</span>
          <div>
            <b>Sentinel Home</b>
            <small>
              {assets.length} correlated assets · {Object.keys(groups).length}{" "}
              segments
            </small>
          </div>
        </article>
        {Object.entries(groups)
          .sort()
          .map(([name, items]) => (
            <section className="topology-segment panel" key={name}>
              <div className="topology-segment-title">
                <span />
                <div>
                  <p className="eyebrow">NETWORK SEGMENT</p>
                  <h2>{name}</h2>
                </div>
                <b>{items.length}</b>
              </div>
              <div className="topology-nodes">
                {items.map((item) => (
                  <article
                    className={
                      !item.linked
                        ? "review"
                        : item.status === "online"
                          ? "online"
                          : ""
                    }
                    key={item.id}
                  >
                    <i />
                    <div>
                      <b>{item.name}</b>
                      <small>
                        {item.address ||
                          item.mac_address ||
                          "No routable identity"}
                      </small>
                      <span>
                        {item.sources.length
                          ? item.sources.join(" + ")
                          : "Sentinel"}
                      </span>
                    </div>
                  </article>
                ))}
              </div>
            </section>
          ))}
      </div>
    </>
  );
}

function NetworkAlerts({
  events,
  csrf,
  refresh,
}: {
  events: NetworkIdentityEvent[];
  csrf: string;
  refresh: () => Promise<void>;
}) {
  const [filter, setFilter] = useState<"open" | "all" | "acknowledged">("open"),
    [busy, setBusy] = useState("");
  const visible = events.filter(
    (item) =>
      filter === "all" ||
      (filter === "open" && !item.acknowledged_at) ||
      (filter === "acknowledged" && item.acknowledged_at),
  );
  async function acknowledge(id: string) {
    setBusy(id);
    try {
      await api.acknowledgeNetworkActivity(id, csrf);
      await refresh();
    } finally {
      setBusy("");
    }
  }
  return (
    <>
      <header>
        <div>
          <p className="eyebrow">NETWORK ATTENTION</p>
          <h1>Network alerts</h1>
          <p>
            Identity changes stay open until you review them. No port scan noise
            is mixed into this queue.
          </p>
        </div>
        <select
          value={filter}
          onChange={(event) => setFilter(event.target.value as typeof filter)}
        >
          <option value="open">Needs review</option>
          <option value="all">All alerts</option>
          <option value="acknowledged">Acknowledged</option>
        </select>
      </header>
      <section className="status-grid network-alert-summary">
        <article className="status-card">
          <p>Needs review</p>
          <strong>{events.filter((x) => !x.acknowledged_at).length}</strong>
          <small>Unacknowledged identity changes</small>
        </article>
        <article className="status-card">
          <p>New identities</p>
          <strong>
            {
              events.filter(
                (x) => x.kind === "identity_seen" && !x.acknowledged_at,
              ).length
            }
          </strong>
          <small>Devices not previously observed</small>
        </article>
        <article className="status-card">
          <p>Address moves</p>
          <strong>
            {
              events.filter(
                (x) => x.kind === "address_changed" && !x.acknowledged_at,
              ).length
            }
          </strong>
          <small>Known identities at a new IP</small>
        </article>
      </section>
      {visible.length === 0 ? (
        <div className="empty-state panel">
          <div>✓</div>
          <h2>Nothing needs review</h2>
          <p>New network identity changes will appear here.</p>
        </div>
      ) : (
        <div className="panel network-alert-list">
          {visible.map((item) => (
            <article
              className={item.acknowledged_at ? "acknowledged" : ""}
              key={item.id}
            >
              <i className={`alert-severity ${item.severity}`} />
              <div>
                <p className="eyebrow">
                  {item.kind === "identity_seen"
                    ? "NEW IDENTITY"
                    : "ADDRESS CHANGED"}{" "}
                  · {item.severity.toUpperCase()}
                </p>
                <h2>{item.name}</h2>
                <p>
                  {item.kind === "address_changed"
                    ? `${item.old_value || "unknown"} → ${item.new_value}`
                    : `First reported as ${item.new_value || "identity only"}`}{" "}
                  by {item.source_name}.
                </p>
              </div>
              <time>{new Date(item.occurred_at).toLocaleString()}</time>
              {item.acknowledged_at ? (
                <span className="tag">Reviewed</span>
              ) : (
                <button
                  disabled={busy === item.id}
                  onClick={() => void acknowledge(item.id)}
                >
                  {busy === item.id ? "Saving…" : "Acknowledge"}
                </button>
              )}
            </article>
          ))}
        </div>
      )}
    </>
  );
}

function NetworkOverview({
  assets,
  loading,
  csrf,
  refresh,
}: {
  assets: NetworkAsset[];
  loading: boolean;
  csrf: string;
  refresh: () => Promise<void>;
}) {
  const [query, setQuery] = useState(""),
    [filter, setFilter] = useState<"all" | "linked" | "review" | "multi">(
      "all",
    ),
    [reviewing, setReviewing] = useState<NetworkAsset | null>(null),
    [target, setTarget] = useState("new"),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const visible = useMemo(
    () =>
      assets.filter((item) => {
        const text =
          `${item.name} ${item.address || ""} ${item.mac_address || ""} ${item.sources.join(" ")}`.toLowerCase();
        return (
          (!query || text.includes(query.toLowerCase())) &&
          (filter === "all" ||
            (filter === "linked" && item.linked) ||
            (filter === "review" && !item.linked) ||
            (filter === "multi" && item.sources.length > 1))
        );
      }),
    [assets, query, filter],
  );
  const review = assets.filter((item) => !item.linked).length,
    multi = assets.filter((item) => item.sources.length > 1).length,
    addressed = assets.filter((item) => item.address).length;
  const canonical = assets.filter((item) => item.linked);
  async function link() {
    if (!reviewing) return;
    setBusy(true);
    setError("");
    try {
      await api.linkNetworkIdentity(
        reviewing.observation_ids,
        target === "new" ? null : target,
        csrf,
      );
      setReviewing(null);
      await refresh();
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Could not link identity",
      );
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <header>
        <div>
          <p className="eyebrow">UNIFIED NETWORK IDENTITY</p>
          <h1>Network overview</h1>
          <p>
            One asset list correlated across Sentinel, Home Assistant, Pi-hole,
            discovery, and agents.
          </p>
        </div>
      </header>
      <section className="status-grid">
        <article className="status-card">
          <p>Canonical assets</p>
          <strong>{assets.length - review}</strong>
          <small>Tracked in Sentinel</small>
        </article>
        <article className="status-card">
          <p>Cross-source matches</p>
          <strong>{multi}</strong>
          <small>Confirmed by multiple systems</small>
        </article>
        <article className="status-card">
          <p>Needs review</p>
          <strong>{review}</strong>
          <small>Observed but not linked</small>
        </article>
        <article className="status-card">
          <p>Address coverage</p>
          <strong>{addressed}</strong>
          <small>Assets with a known IP</small>
        </article>
      </section>
      <div className="panel network-overview-filters">
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search name, IP, MAC, or source"
        />
        <select
          value={filter}
          onChange={(e) => setFilter(e.target.value as typeof filter)}
        >
          <option value="all">All identities</option>
          <option value="linked">Canonical assets</option>
          <option value="multi">Cross-source matches</option>
          <option value="review">Needs review</option>
        </select>
        <b>{visible.length} shown</b>
      </div>
      {loading ? (
        <div className="empty-state panel">
          <h2>Correlating network identities…</h2>
        </div>
      ) : (
        <div className="panel network-asset-list">
          <div className="network-asset heading">
            <span>Asset</span>
            <span>Identity</span>
            <span>Sources</span>
            <span>State</span>
          </div>
          {visible.map((item) => (
            <div className="network-asset" key={item.id}>
              <span>
                <b>{item.name}</b>
                <small>
                  {item.last_seen_at
                    ? `Seen ${new Date(item.last_seen_at).toLocaleString()}`
                    : "No recent observation"}
                </small>
              </span>
              <span>
                <b>{item.address || "No IP yet"}</b>
                <small>{item.mac_address || "Source identity only"}</small>
              </span>
              <span className="source-badges">
                {item.sources.length ? (
                  item.sources.map((source) => <i key={source}>{source}</i>)
                ) : (
                  <i>Sentinel</i>
                )}
              </span>
              <span>
                <b className={item.linked ? "green" : "warning"}>
                  {item.linked ? item.status.replace("_", " ") : "Needs review"}
                </b>
                <small>
                  {item.observations} source observation
                  {item.observations === 1 ? "" : "s"}
                </small>
                {!item.linked && (
                  <button
                    onClick={() => {
                      setReviewing(item);
                      setTarget("new");
                      setError("");
                    }}
                  >
                    Resolve identity
                  </button>
                )}
              </span>
            </div>
          ))}
        </div>
      )}
      {reviewing && (
        <div className="modal-backdrop">
          <div className="panel identity-link-modal">
            <div className="panel-title">
              <div>
                <p className="eyebrow">IDENTITY REVIEW</p>
                <h2>{reviewing.name}</h2>
              </div>
              <button className="close" onClick={() => setReviewing(null)}>
                ×
              </button>
            </div>
            <p>
              Observed as <b>{reviewing.address || "no IP"}</b> /{" "}
              <b>{reviewing.mac_address || "no MAC"}</b> by{" "}
              {reviewing.sources.join(", ")}.
            </p>
            <label>
              Canonical device
              <select
                value={target}
                onChange={(e) => setTarget(e.target.value)}
              >
                <option value="new">Create a new canonical device</option>
                {canonical.map((item) => (
                  <option value={item.id} key={item.id}>
                    {item.name} {item.address ? `(${item.address})` : ""}
                  </option>
                ))}
              </select>
            </label>
            <p className="quiet">
              All {reviewing.observations} grouped source observations will be
              attached together.
            </p>
            {error && <div className="error">{error}</div>}
            <div className="form-actions">
              <button onClick={() => setReviewing(null)}>Cancel</button>
              <button
                className="primary compact"
                disabled={busy}
                onClick={() => void link()}
              >
                {busy
                  ? "Linking…"
                  : target === "new"
                    ? "Create and link"
                    : "Link to device"}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
