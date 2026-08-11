import { useEffect, useMemo, useState } from "react";
import { ActionItem, api } from "./api";

const label = (value: string) => value.replaceAll("_", " ").replace(/\b\w/g, char => char.toUpperCase());

export function ActionsPage({
  items,
  csrf,
  refresh
}: {
  items: ActionItem[];
  csrf: string;
  refresh: () => Promise<void>;
}) {
  const [localItems, setLocalItems] = useState(items);
  const [busy, setBusy] = useState("");
  const [bulkBusy, setBulkBusy] = useState<"build" | "approve" | "release" | "">("");
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [device, setDevice] = useState("all");
  const [readiness, setReadiness] = useState("all");
  const [planStatus, setPlanStatus] = useState("all");
  const [groupBy, setGroupBy] = useState("none");

  useEffect(() => setLocalItems(items), [items]);

  const devices = useMemo(
    () => [...new Set(localItems.map(item => item.device_name || item.address))].sort(),
    [localItems]
  );
  const visible = useMemo(
    () => localItems.filter(item => {
      const text = `${item.cve_id} ${item.title} ${item.device_name || ""} ${item.address} ${item.affected_package || ""}`.toLowerCase();
      const state = item.plan?.status || (item.automation_ready ? "ready" : "locked");
      return (!query || text.includes(query.toLowerCase()))
        && (severity === "all" || item.severity === severity)
        && (device === "all" || (item.device_name || item.address) === device)
        && (readiness === "all" || (readiness === "ready") === item.automation_ready)
        && (planStatus === "all" || state === planStatus);
    }),
    [localItems, query, severity, device, readiness, planStatus]
  );
  const groups = useMemo(() => {
    if (groupBy === "none") return [["All actions", visible] as [string, ActionItem[]]];
    const key = (item: ActionItem) => groupBy === "device"
      ? item.device_name || item.address
      : groupBy === "severity"
        ? item.severity
        : item.plan?.status || (item.automation_ready ? "ready" : "locked");
    return [...new Set(visible.map(key))].sort().map(value => [value, visible.filter(item => key(item) === value)] as [string, ActionItem[]]);
  }, [visible, groupBy]);
  const summary = useMemo(() => ({
    ready: localItems.filter(item => item.automation_ready && !item.plan).length,
    review: localItems.filter(item => item.plan?.status === "draft").length,
    queued: localItems.filter(item => ["approved", "queued", "dispatched"].includes(item.plan?.status || "")).length,
    failed: localItems.filter(item => item.plan?.status === "failed").length,
    completed: localItems.filter(item => item.plan?.status === "completed").length
  }), [localItems]);

  function replaceItem(findingId: string, change: Partial<ActionItem>) {
    setLocalItems(current => current.map(item => item.finding_id === findingId ? {...item, ...change} : item));
  }

  const actionable = visible.filter(item => item.automation_ready && (!item.plan || ["draft", "approved"].includes(item.plan.status)));
  const selectedItems = localItems.filter(item => selected.has(item.finding_id));
  const selectedBuildable = selectedItems.filter(item => item.automation_ready && !item.plan);
  const selectedDrafts = selectedItems.filter(item => item.plan?.status === "draft");
  const selectedApproved = selectedItems.filter(item => item.plan?.status === "approved");

  function toggle(findingId: string) {
    setSelected(current => {
      const next = new Set(current);
      if (next.has(findingId)) next.delete(findingId); else next.add(findingId);
      return next;
    });
  }

  function selectVisible() {
    setSelected(new Set(actionable.map(item => item.finding_id)));
  }

  async function build(item: ActionItem) {
    setBusy(item.finding_id);
    setErrors(current => ({...current, [item.finding_id]: ""}));
    try {
      const plan = await api.buildRemediationPlan(item.finding_id, csrf);
      replaceItem(item.finding_id, {plan});
      void refresh();
    } catch (reason) {
      setErrors(current => ({
        ...current,
        [item.finding_id]: reason instanceof Error ? reason.message : "Unable to build plan"
      }));
    } finally {
      setBusy("");
    }
  }

  async function approve(item: ActionItem) {
    if (!item.plan || !window.confirm(
      `Approve upgrading ${item.plan.package_name} from ${item.plan.installed_version} to ${item.plan.target_version} on ${item.device_name || item.address}? This records approval but does not execute yet.`
    )) return;
    setBusy(item.plan.id);
    setErrors(current => ({...current, [item.finding_id]: ""}));
    try {
      const plan = await api.approveRemediationPlan(item.plan.id, csrf);
      replaceItem(item.finding_id, {plan});
      void refresh();
    } catch (reason) {
      setErrors(current => ({
        ...current,
        [item.finding_id]: reason instanceof Error ? reason.message : "Unable to approve plan"
      }));
    } finally {
      setBusy("");
    }
  }

  async function buildSelected() {
    setBulkBusy("build");
    for (const item of selectedBuildable) await build(item);
    setBulkBusy("");
  }

  async function approveSelected() {
    if (!selectedDrafts.length || !window.confirm(
      `Approve ${selectedDrafts.length} package upgrade plans? Approval is audited. Execution remains queued until the executor is installed.`
    )) return;
    setBulkBusy("approve");
    for (const item of selectedDrafts) {
      if (!item.plan) continue;
      setErrors(current => ({...current, [item.finding_id]: ""}));
      try {
        const plan = await api.approveRemediationPlan(item.plan.id, csrf);
        replaceItem(item.finding_id, {plan});
      } catch (reason) {
        setErrors(current => ({
          ...current,
          [item.finding_id]: reason instanceof Error ? reason.message : "Unable to approve plan"
        }));
      }
    }
    setSelected(new Set());
    setBulkBusy("");
    void refresh();
  }

  async function releaseSelected() {
    if (!selectedApproved.length || !window.confirm(
      `Run ${selectedApproved.length} approved package upgrades? Agents will install each repository candidate and report the result for verification.`
    )) return;
    setBulkBusy("release");
    for (const item of selectedApproved) {
      if (!item.plan) continue;
      try {
        const plan = await api.releaseRemediationPlan(item.plan.id, csrf);
        replaceItem(item.finding_id, {plan});
      } catch (reason) {
        setErrors(current => ({...current,[item.finding_id]:reason instanceof Error?reason.message:"Unable to release plan"}));
      }
    }
    setSelected(new Set());
    setBulkBusy("");
    void refresh();
  }

  async function transition(item: ActionItem, kind: "cancel" | "retry" | "archive") {
    if (!item.plan) return;
    const prompts = {
      cancel: `Cancel the queued upgrade for ${item.plan.package_name}?`,
      retry: `Retry upgrading ${item.plan.package_name} to ${item.plan.target_version}?`,
      archive: `Archive this ${item.plan.status} remediation record?`
    };
    if (!window.confirm(prompts[kind])) return;
    setBusy(item.plan.id);
    try {
      const plan = kind === "cancel"
        ? await api.cancelRemediationPlan(item.plan.id, csrf)
        : kind === "retry"
          ? await api.retryRemediationPlan(item.plan.id, csrf)
          : await api.archiveRemediationPlan(item.plan.id, csrf);
      if (kind === "archive") setLocalItems(current => current.filter(value => value.finding_id !== item.finding_id));
      else replaceItem(item.finding_id, {plan});
      void refresh();
    } catch (reason) {
      setErrors(current => ({...current,[item.finding_id]:reason instanceof Error?reason.message:`Unable to ${kind} plan`}));
    } finally {
      setBusy("");
    }
  }

  async function triage(item: ActionItem, status: "investigating" | "false_positive") {
    if (status === "false_positive" && !window.confirm(`Dismiss ${item.cve_id} as a false positive?`)) return;
    setBusy(item.finding_id);
    try {
      await api.updateFinding(item.finding_id, status, null, csrf);
      if (status === "false_positive") setLocalItems(current => current.filter(value => value.finding_id !== item.finding_id));
      else replaceItem(item.finding_id, {finding_status: status});
      void refresh();
    } catch (reason) {
      setErrors(current => ({...current,[item.finding_id]:reason instanceof Error?reason.message:"Unable to update finding"}));
    } finally {
      setBusy("");
    }
  }

  return <>
    <header><div><p className="eyebrow">IDENTIFY · APPROVE · VERIFY</p><h1>Action Center</h1><p>Prioritized Linux remediation with verified package evidence and an auditable approval gate.</p></div></header>
    <div className="notice panel"><b>Execution safety:</b> Approved plans enter the executor queue, but remain non-executing until the restricted root helper and signed agent protocol are installed.</div>
    <section className="action-summary"><article><b>{summary.ready}</b><span>Ready to build</span></article><article><b>{summary.review}</b><span>Awaiting approval</span></article><article><b>{summary.queued}</b><span>Approved / running</span></article><article className={summary.failed?"danger":""}><b>{summary.failed}</b><span>Failed</span></article><article><b>{summary.completed}</b><span>Completed</span></article></section>
    <div className="panel finding-filters action-filters">
      <label>Search<input value={query} onChange={event => setQuery(event.target.value)} placeholder="CVE, package, or device" /></label>
      <label>Severity<select value={severity} onChange={event => setSeverity(event.target.value)}><option value="all">All</option>{["critical", "high", "medium", "low", "unknown"].map(value => <option key={value}>{value}</option>)}</select></label>
      <label>Device<select value={device} onChange={event => setDevice(event.target.value)}><option value="all">All</option>{devices.map(value => <option key={value}>{value}</option>)}</select></label>
      <label>Readiness<select value={readiness} onChange={event => setReadiness(event.target.value)}><option value="all">All</option><option value="ready">Playbook ready</option><option value="locked">Locked</option></select></label>
      <label>Plan status<select value={planStatus} onChange={event => setPlanStatus(event.target.value)}><option value="all">All</option><option value="ready">Not built</option><option value="draft">Draft</option><option value="approved">Approved</option><option value="queued">Queued</option><option value="dispatched">Executing</option><option value="completed">Completed</option><option value="failed">Failed</option><option value="canceled">Canceled</option><option value="locked">Locked</option></select></label>
      <label>Group by<select value={groupBy} onChange={event => setGroupBy(event.target.value)}><option value="none">None</option><option value="device">Device</option><option value="severity">Severity</option><option value="status">Plan status</option></select></label>
      <b>{visible.length} of {localItems.length}</b>
    </div>
    <div className="panel bulk-actions">
      <div><b>{selected.size} selected</b><span>Select eligible findings to build or approve several package plans together.</span></div>
      <button onClick={selectVisible} disabled={!actionable.length}>Select visible ({actionable.length})</button>
      <button onClick={() => setSelected(new Set())} disabled={!selected.size}>Clear</button>
      <button className="bulk-primary" onClick={() => void buildSelected()} disabled={!selectedBuildable.length || !!bulkBusy}>{bulkBusy === "build" ? "Building…" : `Build selected (${selectedBuildable.length})`}</button>
      <button className="bulk-primary" onClick={() => void approveSelected()} disabled={!selectedDrafts.length || !!bulkBusy}>{bulkBusy === "approve" ? "Approving…" : `Approve selected (${selectedDrafts.length})`}</button>
      <button className="bulk-danger" onClick={() => void releaseSelected()} disabled={!selectedApproved.length || !!bulkBusy}>{bulkBusy === "release" ? "Releasing…" : `Run selected (${selectedApproved.length})`}</button>
    </div>
    {localItems.length === 0
      ? <div className="empty-state panel"><h2>No active remediation work</h2><p>Open or investigating vulnerability findings will appear here.</p></div>
      : visible.length === 0
        ? <div className="empty-state panel"><h2>No matching actions</h2><p>Change or clear the filters above.</p></div>
        : groups.map(([name, groupItems]) => <section className="finding-bucket" key={name}>
          {groupBy !== "none" && <h2>{label(name)}<span>{groupItems.length}</span></h2>}
          <div className="action-list">{groupItems.map(item => <ActionCard
            key={item.finding_id}
            item={item}
            busy={busy}
            error={errors[item.finding_id]}
            selected={selected.has(item.finding_id)}
            toggle={toggle}
            build={build}
            approve={approve}
            transition={transition}
            triage={triage}
          />)}</div>
        </section>)}
  </>;
}

function ActionCard({
  item,
  busy,
  error,
  selected,
  toggle,
  build,
  approve,
  transition,
  triage
}: {
  item: ActionItem;
  busy: string;
  error?: string;
  selected: boolean;
  toggle: (findingId: string) => void;
  build: (item: ActionItem) => Promise<void>;
  approve: (item: ActionItem) => Promise<void>;
  transition: (item: ActionItem, kind: "cancel" | "retry" | "archive") => Promise<void>;
  triage: (item: ActionItem, status: "investigating" | "false_positive") => Promise<void>;
}) {
  const selectable = item.automation_ready && (!item.plan || ["draft", "approved"].includes(item.plan.status));
  return <article className={`panel action-item ${item.known_exploited ? "urgent" : ""} ${selected ? "selected" : ""}`}>
    <div className="action-priority"><label className="action-select"><input type="checkbox" checked={selected} disabled={!selectable} onChange={() => toggle(item.finding_id)} /><span>Select</span></label><strong>{item.priority}</strong><small>PRIORITY</small></div>
    <div>
      <div className="action-title"><span className={`severity ${item.severity}`}>{item.severity}</span><h2>{item.cve_id}</h2>{item.known_exploited && <span className="kev-badge">CISA KEV</span>}</div>
      <p><b>{item.device_name || item.address}</b> · {item.address} · Device criticality: {item.device_criticality || "unassigned"}</p>
      {item.affected_package && <p className="package-evidence"><b>{item.affected_package}</b> {item.installed_version || "unknown"} → {item.fixed_version || "fix not published"}</p>}
      <p>{item.required_action || "Review the vendor advisory and package evidence."}{item.action_due && ` Due ${item.action_due}.`}</p>
      {item.plan
        ? <details className="plan-details" open={item.plan.status==="dispatched"||item.plan.status==="failed"}><summary><b>Plan {item.plan.status}</b><span>{item.plan.package_name} {item.plan.installed_version} → repository upgrade</span></summary><ol><li className={["approved","queued","dispatched","completed","failed"].includes(item.plan.status)?"done":""}>Approval recorded</li><li className={["queued","dispatched","completed","failed"].includes(item.plan.status)?"done":""}>Released to agent</li><li className={item.plan.status==="dispatched"?"active":["completed","failed"].includes(item.plan.status)?"done":""}>Repair package state and install repository candidate</li><li className={item.plan.status==="completed"?"done":item.plan.status==="failed"?"failed":""}>Verify result</li></ol>{item.plan.result_output?<div className="execution-output"><b>{item.plan.status==="dispatched"?"Live agent output":"Execution output"}</b><pre>{item.plan.result_output}</pre></div>:item.plan.status==="dispatched"?<p className="quiet">Waiting for the agent’s first progress update…</p>:null}</details>
        : <div className="automation-locked"><b>{item.automation_ready ? "Plan available" : "Automation locked"}</b><span>{item.automation_blocker}</span></div>}
      {item.plan?.result_error && <div className="error action-error">{item.plan.result_error}</div>}
      {error && <div className="error action-error">{error}</div>}
    </div>
    <div className="action-state">
      <span>{item.finding_status.replace("_", " ")}</span>
      {!item.plan
        ? <button onClick={() => void build(item)} disabled={!item.automation_ready || busy === item.finding_id}>{busy === item.finding_id ? "Building…" : "Build playbook"}</button>
        : item.plan.status === "draft"
          ? <button className="primary compact" onClick={() => void approve(item)} disabled={busy === item.plan.id}>{busy === item.plan.id ? "Approving…" : "Review & approve"}</button>
          : <button disabled>{item.plan.status === "approved" ? "Select to run" : item.plan.status === "dispatched" ? "Executing" : item.plan.status}</button>}
      {!item.plan && !item.automation_ready && <><button onClick={()=>void triage(item,"investigating")} disabled={busy===item.finding_id}>Investigate</button><button className="secondary-action" onClick={()=>void triage(item,"false_positive")} disabled={busy===item.finding_id}>Dismiss</button></>}
      {item.plan && ["approved", "queued"].includes(item.plan.status) && <button className="secondary-action" onClick={() => void transition(item,"cancel")} disabled={busy === item.plan.id}>Cancel</button>}
      {item.plan?.status === "failed" && <button onClick={() => void transition(item,"retry")} disabled={busy === item.plan.id}>Retry</button>}
      {item.plan && ["completed", "failed", "canceled"].includes(item.plan.status) && <button className="secondary-action" onClick={() => void transition(item,"archive")} disabled={busy === item.plan.id}>Archive</button>}
    </div>
  </article>;
}
