import { FormEvent, useState } from "react";
import { api, Device, MaintenanceWindow, ServiceMonitor } from "./api";

const days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];

export function MaintenancePage({ windows, devices, monitors, csrf, refresh }: { windows: MaintenanceWindow[]; devices: Device[]; monitors: ServiceMonitor[]; csrf: string; refresh: () => Promise<void> }) {
  const [open, setOpen] = useState(false); const [busy, setBusy] = useState(false); const [error, setError] = useState("");
  const [name, setName] = useState(""); const [scope, setScope] = useState(""); const [frequency, setFrequency] = useState("weekly");
  const [day, setDay] = useState(0); const [time, setTime] = useState("03:00"); const [duration, setDuration] = useState(60); const [suppress, setSuppress] = useState(true);
  const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  async function submit(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError("");
    try {
      const [kind, id] = scope.split(":");
      await api.createMaintenance({ name, device_id: kind === "device" ? id : null, monitor_id: kind === "monitor" ? id : null, day_of_week: frequency === "weekly" ? day : null, time_of_day: time, duration_minutes: duration, timezone, suppress_notifications: suppress, enabled: true }, csrf);
      setOpen(false); setName(""); setScope(""); await refresh();
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Unable to save window"); } finally { setBusy(false); }
  }
  return <><header><div><p className="eyebrow">PLANNED WORK</p><h1>Maintenance windows</h1><p>Mark recurring downtime as expected while checks and incident history continue.</p></div><button className="primary compact" onClick={() => setOpen(true)}>Add window</button></header>
    {windows.length === 0 ? <div className="empty-state panel"><div>◷</div><h2>No maintenance windows</h2><p>Add a schedule before a reboot, update, or recurring service restart.</p></div> : <div className="maintenance-grid">{windows.map(item => {
      const target = item.monitor_id ? monitors.find(x => x.id === item.monitor_id)?.name : devices.find(x => x.id === item.device_id)?.display_name;
      return <article className={`panel maintenance-card ${item.active ? "active" : ""}`} key={item.id}><div><p className="eyebrow">{item.active ? "ACTIVE NOW" : "RECURRING"}</p><h2>{item.name}</h2><p>{target || "Unknown target"}</p></div><div className="maintenance-schedule"><b>{item.day_of_week === null ? "Every day" : days[item.day_of_week]} at {item.time_of_day}</b><span>{item.duration_minutes} minutes · {item.timezone}</span><small>{item.suppress_notifications ? "Notifications suppressed" : "Notifications remain enabled"}</small></div><button className="danger compact" onClick={async () => { if (confirm(`Remove ${item.name}?`)) { await api.deleteMaintenance(item.id, csrf); await refresh(); } }}>Remove</button></article>;
    })}</div>}
    {open && <div className="modal-backdrop" onMouseDown={() => setOpen(false)}><form className="modal maintenance-modal" onMouseDown={event => event.stopPropagation()} onSubmit={submit}><button type="button" className="modal-close" onClick={() => setOpen(false)}>×</button><p className="eyebrow">EXPECTED OUTAGE</p><h2>Add maintenance window</h2><label>Name<input required maxLength={100} placeholder="Sunday server updates" value={name} onChange={event => setName(event.target.value)} /></label><label>Device or service<select required value={scope} onChange={event => setScope(event.target.value)}><option value="">Select a target</option><optgroup label="Devices">{devices.map(item => <option value={`device:${item.id}`} key={item.id}>{item.display_name}</option>)}</optgroup><optgroup label="Services">{monitors.map(item => <option value={`monitor:${item.id}`} key={item.id}>{item.name}</option>)}</optgroup></select></label><div className="form-row"><label>Repeats<select value={frequency} onChange={event => setFrequency(event.target.value)}><option value="weekly">Weekly</option><option value="daily">Daily</option></select></label>{frequency === "weekly" && <label>Day<select value={day} onChange={event => setDay(Number(event.target.value))}>{days.map((item, index) => <option value={index} key={item}>{item}</option>)}</select></label>}<label>Start time<input type="time" required value={time} onChange={event => setTime(event.target.value)} /></label><label>Duration (minutes)<input type="number" min={5} max={1440} required value={duration} onChange={event => setDuration(Number(event.target.value))} /></label></div><p className="quiet">Timezone: {timezone}</p><label className="check-label"><input type="checkbox" checked={suppress} onChange={event => setSuppress(event.target.checked)} /> Suppress outage and recovery emails during this window</label>{error && <div className="error">{error}</div>}<div className="modal-actions"><button type="button" onClick={() => setOpen(false)}>Cancel</button><button className="primary" disabled={busy}>{busy ? "Saving…" : "Add window"}</button></div></form></div>}
  </>;
}
