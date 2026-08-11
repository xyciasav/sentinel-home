import { useState } from "react";
import { DiscoveredHost, DiscoveryRun, InventorySource, NetworkChange } from "./api";
import { DiscoveryPage } from "./DiscoveryPage";
import { NetworkChangesPage } from "./NetworkChangesPage";
import { SourcesPage } from "./SourcesPage";

export function NetworkPage({sources,run,changes,csrf,refreshSources,refreshDiscovery,refreshDevices,updateHost}:{sources:InventorySource[];run:DiscoveryRun|null;changes:NetworkChange[];csrf:string;refreshSources:()=>Promise<void>;refreshDiscovery:()=>Promise<void>;refreshDevices:()=>Promise<void>;updateHost:(host:DiscoveredHost)=>void}){
  const [section,setSection]=useState<"inventory"|"discovery"|"changes">("inventory");
  return <><div className="network-tabs panel"><button className={section==="inventory"?"active":""} onClick={()=>setSection("inventory")}>Connected inventory</button><button className={section==="discovery"?"active":""} onClick={()=>setSection("discovery")}>Discovery</button><button className={section==="changes"?"active":""} onClick={()=>setSection("changes")}>Changes</button></div>{section==="inventory"?<SourcesPage sources={sources} csrf={csrf} refresh={refreshSources} refreshDevices={refreshDevices}/>:section==="discovery"?<DiscoveryPage run={run} csrf={csrf} refresh={refreshDiscovery} refreshDevices={refreshDevices} updateHost={updateHost}/>:<NetworkChangesPage changes={changes}/>}</>
}
