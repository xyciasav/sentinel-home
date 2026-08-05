import { FormEvent, useState } from "react";
import { api, Device } from "./api";

export function DevicesPage({ devices, csrf, refresh }: { devices: Device[]; csrf: string; refresh: () => Promise<void> }) {
  const [adding, setAdding] = useState(false); const [busy, setBusy] = useState(false); const [error, setError] = useState("");
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError("");
    const data = new FormData(event.currentTarget);
    try {
      await api.createDevice({display_name:data.get("name"),address:data.get("address"),device_type:data.get("type")||null,criticality:data.get("criticality"),monitor_port:Number(data.get("port"))},csrf);
      setAdding(false); await refresh();
    } catch(reason) { setError(reason instanceof Error ? reason.message : "Could not add device"); }
    finally { setBusy(false); }
  }
  return <>
    <header><div><p className="eyebrow">INVENTORY</p><h1>Devices</h1><p>Add the systems you want Sentinel to watch every 30 seconds.</p></div><button className="primary compact" onClick={()=>setAdding(true)}>+ Add device</button></header>
    {adding && <div className="modal-backdrop"><form className="device-form panel" onSubmit={submit}><div className="panel-title"><div><p className="eyebrow">NEW DEVICE</p><h2>Start monitoring</h2></div><button type="button" className="close" onClick={()=>setAdding(false)}>×</button></div><p>Sentinel performs a safe TCP connection check. It does not scan ports or change the device.</p><label>Display name<input name="name" required placeholder="Home Assistant" /></label><label>IP address or local hostname<input name="address" required placeholder="192.168.1.50" /></label><div className="form-row"><label>Device type<select name="type" defaultValue="server"><option value="server">Server</option><option value="workstation">Workstation</option><option value="raspberry-pi">Raspberry Pi</option><option value="home-assistant">Home Assistant</option><option value="iot">IoT</option></select></label><label>TCP port<input name="port" type="number" min="1" max="65535" defaultValue="443" required /></label></div><label>Criticality<select name="criticality" defaultValue="normal"><option value="low">Low</option><option value="normal">Normal</option><option value="high">High</option><option value="critical">Critical</option></select></label>{error&&<div className="error">{error}</div>}<div className="form-actions"><button type="button" onClick={()=>setAdding(false)}>Cancel</button><button className="primary compact" disabled={busy}>{busy?"Checking…":"Add and check"}</button></div></form></div>}
    {devices.length===0 ? <div className="empty-state panel"><div>＋</div><h2>No devices yet</h2><p>Add a server, Raspberry Pi, workstation, Home Assistant host, or other LAN device.</p><button className="primary compact" onClick={()=>setAdding(true)}>Add your first device</button></div> : <div className="device-list panel"><div className="device-row heading"><span>Device</span><span>Target</span><span>Status</span><span>Latency</span><span></span></div>{devices.map(device=><div className="device-row" key={device.id}><span><b>{device.display_name}</b><small>{device.device_type??"Device"}</small></span><span>{device.address}:{device.monitor_port}</span><span><i className={`status-dot ${device.status}`}/>{device.status}</span><span>{device.last_latency_ms ? `${device.last_latency_ms} ms` : "—"}</span><button onClick={async()=>{await api.checkDevice(device.id,csrf);await refresh();}}>Check now</button></div>)}</div>}
  </>;
}
