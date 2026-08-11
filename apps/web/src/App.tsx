import { FormEvent, useEffect, useState } from "react";
import { ActionItem, Agent, api, ApplicationIntegration, ContainerInstance, Device, DiscoveryRun, Incident, InventorySource, MaintenanceWindow, NetworkChange, Notification, OverviewReport, ServiceMonitor, StorageScanJob, StorageTarget, User, VulnerabilityFinding } from "./api";
import { DevicesPage } from "./DevicesPage";
import { ServicesPage } from "./ServicesPage";
import { IncidentsPage } from "./IncidentsPage";
import { NotificationsPage } from "./NotificationsPage";
import { DiscoveryPage } from "./DiscoveryPage";
import { NetworkChangesPage } from "./NetworkChangesPage";
import { VulnerabilitiesPage } from "./VulnerabilitiesPage";
import { StoragePage } from "./StoragePage";
import { ReportsPage } from "./ReportsPage";
import { ActionsPage } from "./ActionsPage";
import { AgentsPage } from "./AgentsPage";
import { ContainersPage } from "./ContainersPage";
import { SourcesPage } from "./SourcesPage";
import { NetworkPage } from "./NetworkPage";
import { MaintenancePage } from "./MaintenancePage";
import { ApplicationsPage } from "./ApplicationsPage";

type View = "loading" | "setup" | "login" | "dashboard";
type Page = "overview" | "devices" | "agents" | "containers" | "network" | "sources" | "discovery" | "changes" | "storage" | "services" | "applications" | "incidents" | "notifications" | "maintenance" | "vulnerabilities" | "actions" | "reports";

const assetPages:Page[]=["devices","agents","containers","network","sources","discovery","changes","storage"];
const monitoringPages:Page[]=["services","applications","incidents","notifications","maintenance"];
const securityPages:Page[]=["vulnerabilities","actions","reports"];

export function App() {
  const [view, setView] = useState<View>("loading");
  const [user, setUser] = useState<User | null>(null);
  const [csrf, setCsrf] = useState("");
  const [health, setHealth] = useState("checking");
  const [version, setVersion] = useState("—");
  const [page, setPage] = useState<Page>("overview");
  const [devices, setDevices] = useState<Device[]>([]);
  const [monitors, setMonitors] = useState<ServiceMonitor[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [maintenance, setMaintenance] = useState<MaintenanceWindow[]>([]);
  const [discovery, setDiscovery] = useState<DiscoveryRun|null>(null);
  const [changes, setChanges] = useState<NetworkChange[]>([]);
  const [findings, setFindings] = useState<VulnerabilityFinding[]>([]);
  const [storageTargets, setStorageTargets] = useState<StorageTarget[]>([]);
  const [storageJobs, setStorageJobs] = useState<StorageScanJob[]>([]);
  const [report, setReport] = useState<OverviewReport|null>(null);
  const [actionItems, setActionItems] = useState<ActionItem[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [containers, setContainers] = useState<ContainerInstance[]>([]);
  const [sources, setSources] = useState<InventorySource[]>([]);
  const [applications, setApplications] = useState<ApplicationIntegration[]>([]);

  useEffect(() => { void initialize(); }, []);
  useEffect(() => {
    if (view !== "dashboard") return;
    const timer = window.setInterval(() => { void loadDevices(); void loadMonitors(); void loadIncidents(); void loadNotifications(); }, 10000);
    return () => window.clearInterval(timer);
  }, [view]);
  useEffect(() => {
    if (view !== "dashboard" || page !== "actions") return;
    const timer = window.setInterval(() => { void loadActions(); }, 5000);
    return () => window.clearInterval(timer);
  }, [view, page]);
  useEffect(() => { if (view === "dashboard" && page === "maintenance") void loadMaintenance(); }, [view, page]);

  async function initialize() {
    try {
      const setup = await api.setupStatus();
      if (!setup.initialized) return setView("setup");
      try {
        const currentUser = await api.me();
        const token = await api.csrf();
        setUser(currentUser); setCsrf(token.csrf_token); setView("dashboard"); void loadStatus(); void loadDevices(); void loadMonitors(); void loadIncidents(); void loadNotifications();
      } catch { setView("login"); }
    } catch { setView("login"); }
  }

  async function loadStatus() {
    const [ready, release] = await Promise.all([api.health(), api.version()]);
    setHealth(ready.status); setVersion(release.version);
  }

  async function loadDevices() { setDevices(await api.devices()); }
  async function loadMonitors() { setMonitors(await api.monitors()); }
  async function loadIncidents() { setIncidents(await api.incidents()); }
  async function loadNotifications() { setNotifications(await api.notifications()); }
  async function loadMaintenance() { setMaintenance(await api.maintenance()); }
  async function loadDiscovery() { setDiscovery(await api.latestDiscovery()); }
  async function loadChanges() { setChanges(await api.networkChanges()); }
  async function loadFindings() { setFindings(await api.vulnerabilities()); }
  async function loadStorage() { const [targets,jobs]=await Promise.all([api.storageTargets(),api.storageJobs()]);setStorageTargets(targets);setStorageJobs(jobs); }
  async function loadReport() { setReport(await api.overviewReport()); }
  async function loadActions() { setActionItems(await api.actionItems()); }
  async function loadAgents() { setAgents(await api.agents()); }
  async function loadContainers() { setContainers(await api.containers()); }
  async function loadSources() { setSources(await api.sources()); }
  async function loadApplications() { setApplications(await api.applications()); }
  async function loadNetwork() { await Promise.all([loadSources(),loadDiscovery(),loadChanges()]); }
  function updateDiscoveryHost(host: DiscoveryRun["hosts"][number]) { setDiscovery(current=>current?{...current,hosts:current.hosts.map(item=>item.id===host.id?host:item)}:current); }
  function updateVulnerability(finding: VulnerabilityFinding) { setFindings(current=>current.map(item=>item.id===finding.id?finding:item)); }

  function authenticated(result: { user: User; csrf_token: string }) {
    setUser(result.user); setCsrf(result.csrf_token); setView("dashboard"); void loadStatus(); void loadDevices(); void loadMonitors(); void loadIncidents(); void loadNotifications();
  }

  if (view === "loading") return <div className="center-screen"><div className="loader" /><p>Starting Sentinel…</p></div>;
  if (view === "setup") return <AuthScreen mode="setup" onSuccess={authenticated} />;
  if (view === "login") return <AuthScreen mode="login" onSuccess={authenticated} />;

  return <div className="app-shell">
    <aside>
      <Brand />
      <nav><button className={page==="overview"?"active":""} onClick={()=>setPage("overview")}>Overview</button><button className={assetPages.includes(page)?"active":""} onClick={()=>setPage("devices")}>Assets</button><button className={monitoringPages.includes(page)?"active":""} onClick={()=>setPage("services")}>Monitoring{incidents.some(i=>i.status==="open")&&<span>{incidents.filter(i=>i.status==="open").length}</span>}</button><button className={securityPages.includes(page)?"active":""} onClick={()=>{setPage("vulnerabilities");void loadFindings()}}>Security</button></nav>
      <div className="sidebar-bottom"><div className="build-version">Sentinel Home <span>v{version}</span></div><a href="/docs">API documentation</a><button onClick={async()=>{await api.logout(csrf);setUser(null);setView("login");}}>Sign out</button></div>
    </aside>
    <main><WorkspaceNav page={page} setPage={setPage} loadAgents={loadAgents} loadContainers={loadContainers} loadNetwork={loadNetwork} loadStorage={loadStorage} loadFindings={loadFindings} loadActions={loadActions} loadReport={loadReport} loadApplications={loadApplications}/>{page==="applications" ? <ApplicationsPage items={applications} csrf={csrf} refresh={loadApplications}/> : page==="maintenance" ? <MaintenancePage windows={maintenance} devices={devices} monitors={monitors} csrf={csrf} refresh={loadMaintenance}/> : page==="network" ? <NetworkPage sources={sources} run={discovery} changes={changes} csrf={csrf} refreshSources={loadSources} refreshDiscovery={loadDiscovery} refreshDevices={loadDevices} updateHost={updateDiscoveryHost}/> : page==="sources" ? <SourcesPage sources={sources} csrf={csrf} refresh={loadSources} refreshDevices={loadDevices}/> : page==="containers" ? <ContainersPage containers={containers} refresh={loadContainers}/> : page==="devices" ? <DevicesPage devices={devices} csrf={csrf} refresh={loadDevices}/> : page==="agents" ? <AgentsPage agents={agents} devices={devices} csrf={csrf} refresh={loadAgents}/> : page==="services" ? <ServicesPage monitors={monitors} devices={devices} csrf={csrf} refresh={loadMonitors}/> : page==="incidents" ? <IncidentsPage incidents={incidents} csrf={csrf} refresh={loadIncidents}/> : page==="notifications" ? <NotificationsPage notifications={notifications} csrf={csrf} refresh={loadNotifications}/> : page==="discovery" ? <DiscoveryPage run={discovery} csrf={csrf} refresh={loadDiscovery} refreshDevices={loadDevices} updateHost={updateDiscoveryHost}/> : page==="changes" ? <NetworkChangesPage changes={changes}/> : page==="vulnerabilities" ? <VulnerabilitiesPage findings={findings} csrf={csrf} updateFinding={updateVulnerability}/> : page==="storage" ? <StoragePage targets={storageTargets} jobs={storageJobs} csrf={csrf} refresh={loadStorage}/> : page==="reports" ? <ReportsPage report={report} refresh={loadReport}/> : page==="actions" ? <ActionsPage items={actionItems} csrf={csrf} refresh={loadActions}/> : <>
      <header><div><p className="eyebrow">CONTROL CENTER</p><h1>Good to see you, {user?.username}</h1><p>Your monitoring foundation is online. Let’s connect your first system.</p></div><div className="live"><i /> Live</div></header>
      <section className="status-grid">
        <StatusCard label="Platform" value={health === "ok" ? "Healthy" : health} tone="green" detail="API, database, and queue" />
        <StatusCard label="Devices" value={String(devices.length)} detail={devices.length ? `${devices.filter(device=>device.status==="online").length} currently online` : "No devices enrolled yet"} />
        <StatusCard label="Active incidents" value={String(incidents.filter(i=>i.status==="open").length)} detail={incidents.some(i=>i.status==="open")?"Investigation may be needed":"Nothing needs attention"} />
        <StatusCard label="Version" value={version} detail="Phase 2 foundation" />
      </section>
      <section className="content-grid">
        <article className="panel getting-started"><div className="panel-title"><div><p className="eyebrow">GETTING STARTED</p><h2>Build your home inventory</h2></div><span>{2+(monitors.length?1:0)} of 4</span></div><Step done title="Deploy Sentinel Home" text="Core services are healthy and persistent."/><Step done={devices.length>0} active={devices.length===0} title="Add your first device" text="Track systems on your private network."/><Step title="Install an endpoint agent" text="Linux and Windows agent enrollment follows inventory."/><Step done={monitors.length>0} active={devices.length>0&&monitors.length===0} title="Create a service monitor" text="Track local HTTP and HTTPS availability."/></article>
        <article className="panel posture"><p className="eyebrow">SECURITY POSTURE</p><h2>Protected by default</h2><ul><li><b>Administrator</b><span>Configured</span></li><li><b>Session security</b><span>Active</span></li><li><b>Network exposure</b><span>LAN only</span></li><li><b>Automated remediation</b><span>Disabled</span></li></ul><p className="quiet">No changes will be made to remote systems without explicit future opt-in.</p></article>
      </section>
    </>}</main>
  </div>;
}

function WorkspaceNav({page,setPage,loadAgents,loadContainers,loadNetwork,loadStorage,loadFindings,loadActions,loadReport,loadApplications}:{page:Page;setPage:(page:Page)=>void;loadAgents:()=>Promise<void>;loadContainers:()=>Promise<void>;loadNetwork:()=>Promise<void>;loadStorage:()=>Promise<void>;loadFindings:()=>Promise<void>;loadActions:()=>Promise<void>;loadReport:()=>Promise<void>;loadApplications:()=>Promise<void>}){
  const open=(target:Page,load?:()=>Promise<void>)=>{setPage(target);if(load)void load()};
  const items:([Page,string,(()=>Promise<void>)?])[]=assetPages.includes(page)?[["devices","Devices"],["agents","Agents",loadAgents],["containers","Containers",loadContainers],["network","Network",loadNetwork],["storage","Storage",loadStorage]]:monitoringPages.includes(page)?[["services","Services"],["applications","Applications",loadApplications],["incidents","Incidents"],["notifications","Notifications"],["maintenance","Maintenance"]]:securityPages.includes(page)?[["vulnerabilities","Vulnerabilities",loadFindings],["actions","Action Center",loadActions],["reports","Reports",loadReport]]:[];
  return items.length?<div className="workspace-nav" aria-label="Workspace sections">{items.map(([target,label,load])=><button key={target} className={page===target?"active":""} onClick={()=>open(target,load)}>{label}</button>)}</div>:null;
}

function Brand(){return <div className="brand"><span className="brand-mark">S</span><div><strong>Sentinel</strong><small>HOME NETWORK</small></div></div>}

function AuthScreen({mode,onSuccess}:{mode:"setup"|"login";onSuccess:(result:{user:User;csrf_token:string})=>void}){
  const [username,setUsername]=useState("");const [password,setPassword]=useState("");const [error,setError]=useState("");const [busy,setBusy]=useState(false);
  async function submit(event:FormEvent){event.preventDefault();setBusy(true);setError("");try{onSuccess(mode==="setup"?await api.bootstrap(username,password):await api.login(username,password))}catch(reason){setError(reason instanceof Error?reason.message:"Unable to continue")}finally{setBusy(false)}}
  return <div className="auth-layout"><section className="auth-story"><Brand/><div><p className="eyebrow">VISIBILITY WITHOUT THE NOISE</p><h1>Your network.<br/>Understood.</h1><p>One private control center for the systems, services, and containers that keep your home running.</p></div><div className="trust-row"><span>Self-hosted</span><span>Observation only</span><span>Open source</span></div></section><section className="auth-form"><form onSubmit={submit}><p className="eyebrow">{mode==="setup"?"FIRST-RUN SETUP":"WELCOME BACK"}</p><h2>{mode==="setup"?"Create your administrator":"Sign in to Sentinel"}</h2><p>{mode==="setup"?"This account stays on your server and controls access to your network data.":"Use your local administrator account."}</p><label>Username<input autoFocus autoComplete="username" value={username} onChange={e=>setUsername(e.target.value)} minLength={3} required/></label><label>Password<input type="password" autoComplete={mode==="setup"?"new-password":"current-password"} value={password} onChange={e=>setPassword(e.target.value)} minLength={12} required/></label>{mode==="setup"&&<small>Use at least 12 characters. A password manager is recommended.</small>}{error&&<div className="error">{error}</div>}<button className="primary" disabled={busy}>{busy?"Please wait…":mode==="setup"?"Create account":"Sign in"}</button></form></section></div>
}

function StatusCard({label,value,detail,tone}:{label:string;value:string;detail:string;tone?:string}){return <article className="status-card"><p>{label}</p><strong className={tone}>{value}</strong><small>{detail}</small></article>}
function Step({title,text,done,active}:{title:string;text:string;done?:boolean;active?:boolean}){return <div className={`step ${active?"active":""}`}><span>{done?"✓":""}</span><div><b>{title}</b><p>{text}</p></div></div>}
