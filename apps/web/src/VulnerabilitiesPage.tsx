import { useMemo, useState } from "react";
import { api, VulnerabilityFinding } from "./api";

const statuses = ["open", "investigating", "accepted_risk", "false_positive", "resolved", "ignored"];
const label = (value: string) => value.replaceAll("_", " ");

export function VulnerabilitiesPage({findings, csrf, updateFinding}: {findings: VulnerabilityFinding[]; csrf: string; updateFinding: (finding: VulnerabilityFinding) => void}) {
  const [statusFilter, setStatusFilter] = useState("active");
  const [classification, setClassification] = useState("actionable");
  const [severity, setSeverity] = useState("all");
  const [host, setHost] = useState("all");
  const [priority, setPriority] = useState("all");
  const [groupBy, setGroupBy] = useState("none");
  const [query, setQuery] = useState("");
  const hosts = [...new Set(findings.map(finding => finding.address))].sort();
  const visible = useMemo(() => findings.filter(finding => {
    const active = ["open", "investigating"].includes(finding.status);
    const unscored = finding.severity === "unknown" && !finding.known_exploited;
    return (statusFilter === "all" || (statusFilter === "active" ? active : finding.status === statusFilter))
      && (classification === "all" || (classification === "actionable" ? !unscored : unscored))
      && (severity === "all" || finding.severity === severity)
      && (host === "all" || finding.address === host)
      && (priority === "all" || (priority === "kev" && finding.known_exploited))
      && (!query || `${finding.cve_id} ${finding.description} ${finding.cpe}`.toLowerCase().includes(query.toLowerCase()));
  }), [findings, statusFilter, classification, severity, host, priority, query]);
  const groups = useMemo(() => {
    if (groupBy === "none") return [["All findings", visible]] as [string, VulnerabilityFinding[]][];
    const key = (finding: VulnerabilityFinding) => groupBy === "host" ? finding.address : groupBy === "severity" ? finding.severity : finding.status;
    return [...new Set(visible.map(key))].sort().map(value => [label(value), visible.filter(finding => key(finding) === value)] as [string, VulnerabilityFinding[]]);
  }, [visible, groupBy]);
  async function changeStatus(finding: VulnerabilityFinding, status: string) {
    updateFinding(await api.updateFinding(finding.id, status, finding.user_notes, csrf));
  }
  return <>
    <header><div><p className="eyebrow">EVIDENCE-BASED FINDINGS</p><h1>Vulnerabilities</h1><p>Exact service and installed-package matches with triage and exploitation priority.</p></div></header>
    <div className="notice panel"><b>Actionable is the default:</b> Unscored advisories without known exploitation are tracked separately and do not count against current posture.</div>
    {findings.length === 0 ? <div className="empty-state panel"><h2>No findings yet</h2><p>Inspect a host in Discovery or scan an updated Linux agent’s package inventory.</p></div> : <>
      <div className="panel finding-filters">
        <label>Search<input value={query} onChange={event => setQuery(event.target.value)} placeholder="CVE, product, or text"/></label>
        <label>View<select value={classification} onChange={event => setClassification(event.target.value)}><option value="actionable">Actionable</option><option value="unscored">Unscored / informational</option><option value="all">Everything</option></select></label>
        <label>Status<select value={statusFilter} onChange={event => setStatusFilter(event.target.value)}><option value="active">Active</option><option value="all">All</option>{statuses.map(status => <option value={status} key={status}>{label(status)}</option>)}</select></label>
        <label>Severity<select value={severity} onChange={event => setSeverity(event.target.value)}><option value="all">All</option>{["critical", "high", "medium", "low", "unknown"].map(value => <option key={value}>{value}</option>)}</select></label>
        <label>Device<select value={host} onChange={event => setHost(event.target.value)}><option value="all">All</option>{hosts.map(address => <option key={address}>{address}</option>)}</select></label>
        <label>Priority<select value={priority} onChange={event => setPriority(event.target.value)}><option value="all">All</option><option value="kev">CISA KEV only</option></select></label>
        <label>Group by<select value={groupBy} onChange={event => setGroupBy(event.target.value)}><option value="none">None</option><option value="host">Device</option><option value="severity">Severity</option><option value="status">Status</option></select></label>
        <b>{visible.length} of {findings.length}</b>
      </div>
      {visible.length === 0 ? <div className="empty-state panel"><h2>No matching findings</h2><p>Change or clear the filters above.</p></div> : groups.map(([name, items]) => <section className="finding-bucket" key={name}>
        <h2>{groupBy === "none" ? null : <>{name}<span>{items.length}</span></>}</h2>
        <div className="finding-grid">{items.map(finding => <article className={`panel finding ${finding.known_exploited ? "kev" : ""}`} key={finding.id}>
          <div><span className={`severity ${finding.severity}`}>{finding.severity}</span><b>{finding.cve_id}</b>{finding.known_exploited && <span className="kev-badge">CISA KEV</span>}<small>CVSS {finding.cvss_score || "unscored"}</small><select value={finding.status} onChange={event => void changeStatus(finding, event.target.value)}>{statuses.map(status => <option value={status} key={status}>{label(status)}</option>)}</select></div>
          <p>{finding.description}</p>
          {finding.affected_package && <p className="package-evidence"><b>{finding.affected_package}</b> {finding.installed_version || "unknown"} → {finding.fixed_version || "fix not published"} · {finding.detection_method}</p>}
          {finding.required_action && <p className="required-action"><b>Required action:</b> {finding.required_action}{finding.action_due && ` · Due ${finding.action_due}`}</p>}
          <small>{finding.address} · {finding.cpe}</small>
        </article>)}</div>
      </section>)}
    </>}
  </>;
}
