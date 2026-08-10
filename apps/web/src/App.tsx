import { FormEvent, useEffect, useState } from "react";
import { api, Device, ServiceMonitor, User } from "./api";
import { DevicesPage } from "./DevicesPage";
import { ServicesPage } from "./ServicesPage";

type View = "loading" | "setup" | "login" | "dashboard";

export function App() {
  const [view, setView] = useState<View>("loading");
  const [user, setUser] = useState<User | null>(null);
  const [csrf, setCsrf] = useState("");
  const [health, setHealth] = useState("checking");
  const [version, setVersion] = useState("—");
  const [page, setPage] = useState<"overview" | "devices" | "services">("overview");
  const [devices, setDevices] = useState<Device[]>([]);
  const [monitors, setMonitors] = useState<ServiceMonitor[]>([]);

  useEffect(() => { void initialize(); }, []);
  useEffect(() => {
    if (view !== "dashboard") return;
    const timer = window.setInterval(() => { void loadDevices(); void loadMonitors(); }, 10000);
    return () => window.clearInterval(timer);
  }, [view]);

  async function initialize() {
    try {
      const setup = await api.setupStatus();
      if (!setup.initialized) return setView("setup");
      try {
        const currentUser = await api.me();
        const token = await api.csrf();
        setUser(currentUser); setCsrf(token.csrf_token); setView("dashboard"); void loadStatus(); void loadDevices(); void loadMonitors();
      } catch { setView("login"); }
    } catch { setView("login"); }
  }

  async function loadStatus() {
    const [ready, release] = await Promise.all([api.health(), api.version()]);
    setHealth(ready.status); setVersion(release.version);
  }

  async function loadDevices() { setDevices(await api.devices()); }
  async function loadMonitors() { setMonitors(await api.monitors()); }

  function authenticated(result: { user: User; csrf_token: string }) {
    setUser(result.user); setCsrf(result.csrf_token); setView("dashboard"); void loadStatus(); void loadDevices(); void loadMonitors();
  }

  if (view === "loading") return <div className="center-screen"><div className="loader" /><p>Starting Sentinel…</p></div>;
  if (view === "setup") return <AuthScreen mode="setup" onSuccess={authenticated} />;
  if (view === "login") return <AuthScreen mode="login" onSuccess={authenticated} />;

  return <div className="app-shell">
    <aside>
      <Brand />
      <nav><button className={page==="overview"?"active":""} onClick={()=>setPage("overview")}>Overview</button><button className={page==="devices"?"active":""} onClick={()=>setPage("devices")}>Devices</button><button className={page==="services"?"active":""} onClick={()=>setPage("services")}>Services</button>{["Incidents","Vulnerabilities","Containers","Storage"].map(item => <button key={item} disabled>{item}<span>Soon</span></button>)}</nav>
      <div className="sidebar-bottom"><a href="/docs">API documentation</a><button onClick={async()=>{await api.logout(csrf);setUser(null);setView("login");}}>Sign out</button></div>
    </aside>
    <main>{page==="devices" ? <DevicesPage devices={devices} csrf={csrf} refresh={loadDevices}/> : page==="services" ? <ServicesPage monitors={monitors} devices={devices} csrf={csrf} refresh={loadMonitors}/> : <>
      <header><div><p className="eyebrow">CONTROL CENTER</p><h1>Good to see you, {user?.username}</h1><p>Your monitoring foundation is online. Let’s connect your first system.</p></div><div className="live"><i /> Live</div></header>
      <section className="status-grid">
        <StatusCard label="Platform" value={health === "ok" ? "Healthy" : health} tone="green" detail="API, database, and queue" />
        <StatusCard label="Devices" value={String(devices.length)} detail={devices.length ? `${devices.filter(device=>device.status==="online").length} currently online` : "No devices enrolled yet"} />
        <StatusCard label="Services down" value={String(monitors.filter(m=>m.status==="down").length)} detail={`${monitors.length} service${monitors.length===1?"":"s"} monitored`} />
        <StatusCard label="Version" value={version} detail="Phase 2 foundation" />
      </section>
      <section className="content-grid">
        <article className="panel getting-started"><div className="panel-title"><div><p className="eyebrow">GETTING STARTED</p><h2>Build your home inventory</h2></div><span>{2+(monitors.length?1:0)} of 4</span></div><Step done title="Deploy Sentinel Home" text="Core services are healthy and persistent."/><Step done={devices.length>0} active={devices.length===0} title="Add your first device" text="Track systems on your private network."/><Step title="Install an endpoint agent" text="Linux and Windows agent enrollment follows inventory."/><Step done={monitors.length>0} active={devices.length>0&&monitors.length===0} title="Create a service monitor" text="Track local HTTP and HTTPS availability."/></article>
        <article className="panel posture"><p className="eyebrow">SECURITY POSTURE</p><h2>Protected by default</h2><ul><li><b>Administrator</b><span>Configured</span></li><li><b>Session security</b><span>Active</span></li><li><b>Network exposure</b><span>LAN only</span></li><li><b>Automated remediation</b><span>Disabled</span></li></ul><p className="quiet">No changes will be made to remote systems without explicit future opt-in.</p></article>
      </section>
    </>}</main>
  </div>;
}

function Brand(){return <div className="brand"><span className="brand-mark">S</span><div><strong>Sentinel</strong><small>HOME NETWORK</small></div></div>}

function AuthScreen({mode,onSuccess}:{mode:"setup"|"login";onSuccess:(result:{user:User;csrf_token:string})=>void}){
  const [username,setUsername]=useState("");const [password,setPassword]=useState("");const [error,setError]=useState("");const [busy,setBusy]=useState(false);
  async function submit(event:FormEvent){event.preventDefault();setBusy(true);setError("");try{onSuccess(mode==="setup"?await api.bootstrap(username,password):await api.login(username,password))}catch(reason){setError(reason instanceof Error?reason.message:"Unable to continue")}finally{setBusy(false)}}
  return <div className="auth-layout"><section className="auth-story"><Brand/><div><p className="eyebrow">VISIBILITY WITHOUT THE NOISE</p><h1>Your network.<br/>Understood.</h1><p>One private control center for the systems, services, and containers that keep your home running.</p></div><div className="trust-row"><span>Self-hosted</span><span>Observation only</span><span>Open source</span></div></section><section className="auth-form"><form onSubmit={submit}><p className="eyebrow">{mode==="setup"?"FIRST-RUN SETUP":"WELCOME BACK"}</p><h2>{mode==="setup"?"Create your administrator":"Sign in to Sentinel"}</h2><p>{mode==="setup"?"This account stays on your server and controls access to your network data.":"Use your local administrator account."}</p><label>Username<input autoFocus autoComplete="username" value={username} onChange={e=>setUsername(e.target.value)} minLength={3} required/></label><label>Password<input type="password" autoComplete={mode==="setup"?"new-password":"current-password"} value={password} onChange={e=>setPassword(e.target.value)} minLength={12} required/></label>{mode==="setup"&&<small>Use at least 12 characters. A password manager is recommended.</small>}{error&&<div className="error">{error}</div>}<button className="primary" disabled={busy}>{busy?"Please wait…":mode==="setup"?"Create account":"Sign in"}</button></form></section></div>
}

function StatusCard({label,value,detail,tone}:{label:string;value:string;detail:string;tone?:string}){return <article className="status-card"><p>{label}</p><strong className={tone}>{value}</strong><small>{detail}</small></article>}
function Step({title,text,done,active}:{title:string;text:string;done?:boolean;active?:boolean}){return <div className={`step ${active?"active":""}`}><span>{done?"✓":""}</span><div><b>{title}</b><p>{text}</p></div></div>}
