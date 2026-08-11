import { OverviewReport } from "./api";

const percent=(value:number|null)=>value===null?"No data":`${value.toFixed(2)}%`;
const size=(bytes:number)=>bytes>=1_073_741_824?`${(bytes/1_073_741_824).toFixed(1)} GB`:`${(bytes/1_048_576).toFixed(1)} MB`;

export function ReportsPage({report,refresh}:{report:OverviewReport|null;refresh:()=>Promise<void>}) {
  if(!report)return <><header><div><p className="eyebrow">OBSERVABILITY SUMMARY</p><h1>Reports</h1><p>Loading collected monitoring data…</p></div></header></>;
  const vulnerabilities=Object.entries(report.active_vulnerabilities).sort(([a],[b])=>a.localeCompare(b));
  const remediation=Object.entries(report.remediation_status).filter(([status])=>status!=="archived").sort(([a],[b])=>a.localeCompare(b));
  return <>
    <header><div><p className="eyebrow">OPERATIONS AND SECURITY</p><h1>Reports</h1><p>Current posture and measured reliability, generated {new Date(report.generated_at).toLocaleString()}.</p></div><button className="primary compact" onClick={()=>void refresh()}>Refresh report</button></header>
    <section className="status-grid report-cards">
      <article className="status-card"><p>24-hour uptime</p><strong>{percent(report.last_24_hours.uptime_percent)}</strong><small>{report.last_24_hours.checks.toLocaleString()} checks · {report.last_24_hours.average_response_ms??"—"} ms average</small></article>
      <article className="status-card"><p>Agent coverage</p><strong className={report.agents_connected===report.agents_total?"green":""}>{report.agents_connected} / {report.agents_total}</strong><small>{report.agents_current} running agent v0.5.2 + executor v0.2.0</small></article>
      <article className="status-card"><p>Package vulnerabilities</p><strong>{report.package_vulnerabilities}</strong><small>Verified from installed Linux packages</small></article>
      <article className="status-card"><p>Known exploited</p><strong className={report.known_exploited?"report-danger":"green"}>{report.known_exploited}</strong><small>Active CISA KEV findings</small></article>
    </section>
    <section className="report-grid">
      <article className="panel"><p className="eyebrow">SERVICE RELIABILITY · 24 HOURS</p><h2>Uptime by service</h2>{report.services.length===0?<p className="quiet">Create service monitors to begin collecting uptime.</p>:<div className="service-report">{report.services.map(service=><div key={service.id}><div><b><i className={`status-dot ${service.status}`}/>{service.name}</b><span>{percent(service.uptime_percent)}</span></div><div className="uptime-track"><i style={{width:`${service.uptime_percent??0}%`}}/></div><small>{service.checks} checks · {service.average_response_ms??"—"} ms average</small></div>)}</div>}</article>
      <article className="panel"><p className="eyebrow">SECURITY AND CAPACITY</p><h2>Attention summary</h2><ul className="report-list"><li><span>Open incidents</span><b>{report.open_incidents}</b></li><li><span>Network changes, 7 days</span><b>{report.network_changes_7_days}</b></li>{vulnerabilities.map(([severity,count])=><li key={severity}><span>{severity} vulnerabilities</span><b>{count}</b></li>)}<li><span>Storage recommendations</span><b>{report.storage_recommendations}</b></li><li><span>Flagged storage</span><b>{size(report.storage_flagged_bytes)}</b></li></ul></article>
    </section>
    <section className="panel report-section"><div className="panel-title"><div><p className="eyebrow">LINUX REMEDIATION</p><h2>Playbook outcomes</h2></div></div>{remediation.length===0?<p className="quiet">No remediation plans yet.</p>:<div className="remediation-summary">{remediation.map(([status,count])=><div key={status}><b>{count}</b><span>{status.replaceAll("_"," ")}</span></div>)}</div>}</section>
    <section className="panel report-section"><p className="eyebrow">RISK BY DEVICE</p><h2>Where attention is needed</h2><div className="device-risk-table"><div className="device-risk-row heading"><span>Device</span><span>Agent</span><span>Active</span><span>Critical / high</span><span>CISA KEV</span><span>Failed fixes</span></div>{report.devices.map(device=><div className={`device-risk-row ${device.known_exploited||device.remediation_failed?"attention":""}`} key={device.id}><span><b>{device.name}</b><small>{device.criticality} criticality</small></span><span>{device.agent_version?<><i className={`status-dot ${device.agent_connected?"online":"offline"}`}/>{device.agent_version}</>:"Not installed"}</span><b>{device.active_vulnerabilities}</b><b>{device.critical_high}</b><b>{device.known_exploited}</b><b>{device.remediation_failed}</b></div>)}</div></section>
  </>;
}
