import { useEffect, useState } from "react";
import { api, Dashboard } from "./api";

export function OverviewPage({username, version, health}: {username: string; version: string; health: string}) {
  const [data, setData] = useState<Dashboard | null>(null);
  const [busy, setBusy] = useState(false);
  async function load() {
    setBusy(true);
    try { setData(await api.dashboard()); } finally { setBusy(false); }
  }
  useEffect(() => {
    void load();
    const timer = setInterval(() => void load(), 30000);
    return () => clearInterval(timer);
  }, []);
  if (!data) return <header><div><p className="eyebrow">CONTROL CENTER</p><h1>Good to see you, {username}</h1><p>Loading your operational picture…</p></div></header>;
  const alerts = data.network_alerts_open + data.container_alerts_open + data.application_alerts_open;
  return <>
    <header><div><p className="eyebrow">CONTROL CENTER</p><h1>Good to see you, {username}</h1><p>Everything Sentinel knows about your network, systems, services, and applications.</p></div><button onClick={() => void load()} disabled={busy}>{busy ? "Refreshing…" : "Refresh data"}</button></header>
    <section className="status-grid dashboard-primary">
      <Card label="Platform" value={health === "ok" ? "Healthy" : health} detail={`Sentinel ${version}`}/>
      <Card label="Devices" value={`${data.devices_online} / ${data.devices_total}`} detail={`${data.appliance_devices} appliances · no agent expected`}/>
      <Card label="Services" value={`${data.services_up} / ${data.services_total}`} detail={`${data.open_incidents} active incidents`} danger={data.open_incidents > 0}/>
      <Card label="Open alerts" value={String(alerts)} detail={`${data.network_alerts_open} network · ${data.container_alerts_open} container · ${data.application_alerts_open} app`} danger={alerts > 0}/>
    </section>
    <section className="dashboard-grid">
      <article className="panel dashboard-posture"><p className="eyebrow">COVERAGE AND RISK</p><h2>Current posture</h2><div className="posture-metrics">
        <Metric label="Connected agents" value={`${data.agents_connected} / ${data.agents_expected}`}/>
        <Metric label="Healthy applications" value={`${data.applications_healthy} / ${data.applications_total}`}/>
        <Metric label="Actionable vulnerabilities" value={String(data.vulnerabilities_active)} danger={data.vulnerabilities_active > 0}/>
        <Metric label="Unscored / informational" value={String(data.vulnerabilities_unscored)}/>
        <Metric label="Critical / high" value={String(data.vulnerabilities_critical_high)} danger={data.vulnerabilities_critical_high > 0}/>
        <Metric label="Known exploited" value={String(data.known_exploited)} danger={data.known_exploited > 0}/>
      </div></article>
      <article className="panel dashboard-attention"><div className="panel-title"><div><p className="eyebrow">RECENT ATTENTION</p><h2>What changed</h2></div><span>{data.attention.filter(item => !item.acknowledged).length} unreviewed</span></div>{data.attention.length === 0 ? <p className="quiet">No attention events recorded yet.</p> : <div className="attention-feed">{data.attention.map((item, index) => <div className={item.acknowledged ? "reviewed" : ""} key={`${item.source}-${item.occurred_at}-${index}`}><i className={`alert-severity ${item.severity}`}/><span><small>{item.source.toUpperCase()}</small><b>{item.title}</b><p>{item.detail}</p></span><time>{new Date(item.occurred_at).toLocaleString()}</time></div>)}</div>}</article>
    </section>
  </>;
}

function Card({label, value, detail, danger}: {label: string; value: string; detail: string; danger?: boolean}) {
  return <article className="status-card"><p>{label}</p><strong className={danger ? "report-danger" : "green"}>{value}</strong><small>{detail}</small></article>;
}
function Metric({label, value, danger}: {label: string; value: string; danger?: boolean}) {
  return <div><span>{label}</span><b className={danger ? "report-danger" : ""}>{value}</b></div>;
}
