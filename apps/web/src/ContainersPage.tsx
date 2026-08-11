import { useMemo, useState } from "react";
import { ContainerInstance } from "./api";

export function ContainersPage({containers,refresh}:{containers:ContainerInstance[];refresh:()=>Promise<void>}) {
  const [search,setSearch]=useState("");
  const [device,setDevice]=useState("all");
  const [state,setState]=useState("all");
  const devices=[...new Set(containers.map(item=>item.device_name))].sort();
  const visible=useMemo(()=>containers.filter(item=>(!search||`${item.name} ${item.image}`.toLowerCase().includes(search.toLowerCase()))&&(device==="all"||item.device_name===device)&&(state==="all"||(state==="unhealthy"?item.health==="unhealthy":item.state===state))),[containers,search,device,state]);
  const running=containers.filter(item=>item.state==="running").length;
  const unhealthy=containers.filter(item=>item.health==="unhealthy").length;
  const stopped=containers.filter(item=>item.state!=="running").length;
  return <>
    <header><div><p className="eyebrow">READ-ONLY DOCKER VISIBILITY</p><h1>Containers</h1><p>Inventory and runtime health reported securely by your Linux agents.</p></div><button onClick={()=>void refresh()}>Refresh inventory</button></header>
    <section className="status-grid container-summary"><Status label="Total" value={containers.length}/><Status label="Running" value={running} tone="green"/><Status label="Unhealthy" value={unhealthy} tone={unhealthy?"red":"green"}/><Status label="Stopped" value={stopped} tone={stopped?"amber":undefined}/></section>
    <section className="panel">
      <div className="filter-row"><input aria-label="Search containers" placeholder="Search name or image" value={search} onChange={e=>setSearch(e.target.value)}/><select aria-label="Filter by device" value={device} onChange={e=>setDevice(e.target.value)}><option value="all">All devices</option>{devices.map(name=><option key={name}>{name}</option>)}</select><select aria-label="Filter by state" value={state} onChange={e=>setState(e.target.value)}><option value="all">All states</option><option value="running">Running</option><option value="exited">Exited</option><option value="paused">Paused</option><option value="unhealthy">Unhealthy</option></select></div>
      {!containers.length?<div className="empty-state"><h2>No container inventory yet</h2><p>Update a Linux agent to v0.5.0. Docker inventory appears automatically within five minutes when Docker is installed.</p></div>:!visible.length?<div className="empty-state"><h2>No matching containers</h2><p>Try clearing one of the filters.</p></div>:<div className="container-list">{visible.map(item=><article className="container-row" key={item.id}><div className={`container-state ${item.health==="unhealthy"||item.state!=="running"?"bad":"good"}`}/><div className="container-identity"><strong>{item.name}</strong><small>{item.image}</small></div><div><small>Host</small><b>{item.device_name}</b><span>{item.hostname}</span></div><div><small>Runtime</small><b>{item.state}{item.health?` · ${item.health}`:""}</b><span>{item.status||"No runtime detail"}</span></div><div><small>Ports</small><b>{item.ports||"None published"}</b><span>{item.restart_count} restarts</span></div>{item.stale&&<span className="tag warning">Stale</span>}</article>)}</div>}
    </section>
  </>;
}

function Status({label,value,tone}:{label:string;value:number;tone?:string}){return <article className="status-card"><p>{label}</p><strong className={tone}>{value}</strong><small>reported containers</small></article>}
