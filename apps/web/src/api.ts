export type User = { id: string; username: string; is_admin: boolean };
export type AuthResult = { user: User; csrf_token: string; expires_at: string };
export type Device = {
  id: string; display_name: string; address: string; hostname: string | null;
  device_type: string | null; criticality: string; trust: string; monitor_port: number | null;
  status: string; last_checked_at: string | null; last_latency_ms: number | null;
  last_failure_reason: string | null; notes: string | null;
  alerts_muted_until: string | null; alert_mute_reason: string | null; notifications_muted:boolean;
};
export type ServiceMonitor = {
  id:string; name:string; group_name:string|null; target_scope:"internal"|"external"; url:string; device_id:string|null; expected_status:number;
  expected_text:string|null; timeout_seconds:number; verify_tls:boolean; enabled:boolean;
  severity:string; status:string; last_checked_at:string|null; last_success_at:string|null;
  notifications_muted:boolean;
  outage_started_at:string|null; last_response_ms:number|null; last_status_code:number|null;
  last_failure_reason:string|null;
};
export type IncidentEvent = {kind:string;message:string;occurred_at:string};
export type Incident = {id:string;monitor_id:string;title:string;severity:string;status:string;summary:string;started_at:string;recovered_at:string|null;acknowledged_at:string|null;events:IncidentEvent[]};
export type Notification = {id:string;incident_id:string|null;kind:string;recipient:string|null;subject:string;status:string;error:string|null;created_at:string;sent_at:string|null};
export type DiscoveredHost = {id:string;address:string;open_ports:number[];state:string;device_id:string|null;discovered_at:string};
export type DiscoveryRun = {id:string;subnet:string;status:string;hosts_checked:number;hosts_found:number;started_at:string;completed_at:string|null;hosts:DiscoveredHost[]};
export type NetworkChange = {id:string;device_id:string|null;address:string;kind:string;port:number;service:string|null;detected_at:string};
export type VulnerabilityFinding = {id:string;device_id:string|null;address:string;cve_id:string;title:string;description:string;severity:string;cvss_score:string|null;known_exploited:boolean;required_action:string|null;action_due:string|null;cpe:string;status:string;user_notes:string|null;affected_package:string|null;installed_version:string|null;fixed_version:string|null;detection_method:string|null;first_seen_at:string;last_seen_at:string};
export type StorageFinding = {id:string;relative_path:string;item_type:string;size_bytes:number;modified_at:string;reason:string;protected:boolean};
export type StorageTarget = {id:string;name:string;relative_path:string;large_file_bytes:number;old_file_days:number;protected_paths:string;last_scanned_at:string|null;last_total_bytes:number;last_file_count:number;findings:StorageFinding[]};
export type StorageScanJob = {id:string;target_id:string;status:"queued"|"running"|"completed"|"failed";files_scanned:number;findings_count:number;error:string|null;created_at:string;started_at:string|null;completed_at:string|null};
export type ReportWindow = {checks:number;successful:number;uptime_percent:number|null;average_response_ms:number|null};
export type ServiceReport = {id:string;name:string;status:string;checks:number;uptime_percent:number|null;average_response_ms:number|null};
export type DeviceSecurityReport = {id:string;name:string;criticality:string;agent_version:string|null;agent_connected:boolean;active_vulnerabilities:number;critical_high:number;known_exploited:number;remediation_failed:number};
export type OverviewReport = {generated_at:string;last_24_hours:ReportWindow;last_7_days:ReportWindow;services:ServiceReport[];open_incidents:number;incidents_7_days:number;network_changes_7_days:number;active_vulnerabilities:Record<string,number>;known_exploited:number;storage_recommendations:number;storage_flagged_bytes:number;agents_total:number;agents_connected:number;agents_current:number;package_vulnerabilities:number;remediation_status:Record<string,number>;devices:DeviceSecurityReport[]};
export type RemediationPlan = {id:string;finding_id:string;agent_id:string;package_name:string;installed_version:string;target_version:string;operation:string;status:"draft"|"approved"|"queued"|"dispatched"|"completed"|"failed"|"canceled"|"archived";created_at:string;approved_at:string|null;dispatched_at:string|null;completed_at:string|null;result_output:string|null;result_error:string|null};
export type ActionItem = {finding_id:string;cve_id:string;title:string;severity:string;cvss_score:string|null;known_exploited:boolean;required_action:string|null;action_due:string|null;finding_status:string;address:string;device_name:string|null;device_criticality:string|null;automation_ready:boolean;automation_blocker:string;priority:number;affected_package:string|null;installed_version:string|null;fixed_version:string|null;detection_method:string|null;plan:RemediationPlan|null};
export type Agent = {id:string;device_id:string;device_name:string;version:string;executor_version:string|null;platform:string;hostname:string|null;os_name:string|null;os_version:string|null;kernel_version:string|null;last_heartbeat_at:string|null;connected:boolean;cpu_percent:number|null;memory_percent:number|null;disk_percent:number|null;disk_free_bytes:number|null;uptime_seconds:number|null;package_count:number;container_count:number};
export type ContainerInstance = {id:string;agent_id:string;device_id:string;device_name:string;hostname:string|null;container_id:string;name:string;image:string;state:string;health:string|null;status:string|null;ports:string|null;restart_count:number;observed_at:string;stale:boolean};
export type InventorySource = {id:string;name:string;kind:string;base_url:string;enabled:boolean;last_sync_at:string|null;last_sync_status:string;last_sync_error:string|null;device_count:number;importable_count:number;imported_count:number;summary:Record<string,unknown>|null};
export type SourceDevice = {id:string;external_id:string;name:string;address:string|null;mac_address:string|null;manufacturer:string|null;model:string|null;area_name:string|null;imported_device_id:string|null};
export type NetworkAsset = {id:string;name:string;address:string|null;mac_address:string|null;status:string;sources:string[];observations:number;linked:boolean;last_seen_at:string|null;observation_ids:string[]};
export type NetworkIdentityEvent = {id:string;kind:"identity_seen"|"address_changed";name:string;source_name:string;old_value:string|null;new_value:string|null;occurred_at:string};
export type AgentEnrollment = {enrollment_token:string;expires_at:string};
export type AgentMetric = {cpu_percent:number;memory_percent:number;disk_percent:number;disk_free_bytes:number;uptime_seconds:number;collected_at:string};
export type InstalledPackage = {name:string;version:string;architecture:string|null;manager:string;source_name:string|null;source_version:string|null;candidate_version:string|null;observed_at:string};

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const { headers, ...requestOptions } = options;
  const response = await fetch(path, {
    credentials: "same-origin",
    ...requestOptions,
    headers: { "Content-Type": "application/json", ...(headers as Record<string, string> | undefined) }
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({ detail: "Request failed" }));
    const detail = body.detail;
    if (Array.isArray(detail)) {
      const message = detail.map(item => `${item.loc?.slice(1).join(".") || "request"}: ${item.msg}`).join("; ");
      throw new Error(message);
    }
    throw new Error(typeof detail === "string" ? detail : `Request failed (${response.status})`);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export const api = {
  setupStatus: () => request<{ initialized: boolean; administrator_count: number }>("/api/v1/setup/status"),
  me: () => request<User>("/api/v1/auth/me"),
  csrf: () => request<{ csrf_token: string }>("/api/v1/auth/csrf"),
  bootstrap: (username: string, password: string) =>
    request<AuthResult>("/api/v1/auth/bootstrap", {
      method: "POST",
      body: JSON.stringify({ username, password })
    }),
  login: (username: string, password: string) =>
    request<AuthResult>("/api/v1/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password })
    }),
  logout: (csrfToken: string) =>
    request<void>("/api/v1/auth/logout", {
      method: "POST",
      headers: { "X-CSRF-Token": csrfToken }
    }),
  devices: () => request<Device[]>("/api/v1/devices"),
  createDevice: (payload: Record<string, unknown>, csrfToken: string) =>
    request<Device>("/api/v1/devices", { method: "POST", headers: { "X-CSRF-Token": csrfToken }, body: JSON.stringify(payload) }),
  updateDevice: (id: string, payload: Record<string, unknown>, csrfToken: string) =>
    request<Device>(`/api/v1/devices/${id}`, { method: "PUT", headers: { "X-CSRF-Token": csrfToken }, body: JSON.stringify(payload) }),
  checkDevice: (id: string, csrfToken: string) =>
    request<Device>(`/api/v1/devices/${id}/check`, { method: "POST", headers: { "X-CSRF-Token": csrfToken } }),
  monitors: () => request<ServiceMonitor[]>("/api/v1/monitors"),
  createMonitor: (payload: Record<string, unknown>, csrfToken: string) =>
    request<ServiceMonitor>("/api/v1/monitors", { method:"POST", headers:{"X-CSRF-Token":csrfToken}, body:JSON.stringify(payload) }),
  updateMonitor: (id:string, payload:Record<string,unknown>, csrfToken:string) =>
    request<ServiceMonitor>(`/api/v1/monitors/${id}`, { method:"PUT", headers:{"X-CSRF-Token":csrfToken}, body:JSON.stringify(payload) }),
  checkMonitor: (id:string, csrfToken:string) =>
    request<ServiceMonitor>(`/api/v1/monitors/${id}/check`, { method:"POST", headers:{"X-CSRF-Token":csrfToken} }),
  deleteMonitor: (id:string, csrfToken:string) =>
    request<void>(`/api/v1/monitors/${id}`, { method:"DELETE", headers:{"X-CSRF-Token":csrfToken} }),
  incidents: () => request<Incident[]>("/api/v1/incidents"),
  acknowledgeIncident: (id:string, csrfToken:string) =>
    request<Incident>(`/api/v1/incidents/${id}/acknowledge`, { method:"POST", headers:{"X-CSRF-Token":csrfToken} }),
  notifications: () => request<Notification[]>("/api/v1/notifications"),
  testNotification: (csrfToken:string) =>
    request<Notification>("/api/v1/notifications/test", { method:"POST", headers:{"X-CSRF-Token":csrfToken} }),
  dismissNotifications: (ids:string[],csrfToken:string) => request<void>("/api/v1/notifications/dismiss",{method:"POST",headers:{"X-CSRF-Token":csrfToken},body:JSON.stringify({ids})}),
  muteDeviceAlerts: (deviceId:string,minutes:number,reason:string,csrfToken:string) => request<{device_id:string;alerts_muted_until:string|null;alert_mute_reason:string|null}>(`/api/v1/notifications/devices/${deviceId}/mute`,{method:"POST",headers:{"X-CSRF-Token":csrfToken},body:JSON.stringify({minutes,reason})}),
  toggleDeviceNotifications: (deviceId:string,muted:boolean,csrfToken:string) => request<{id:string;notifications_muted:boolean}>(`/api/v1/notifications/devices/${deviceId}/toggle`,{method:"PUT",headers:{"X-CSRF-Token":csrfToken},body:JSON.stringify({muted})}),
  toggleMonitorNotifications: (monitorId:string,muted:boolean,csrfToken:string) => request<{id:string;notifications_muted:boolean}>(`/api/v1/notifications/monitors/${monitorId}/toggle`,{method:"PUT",headers:{"X-CSRF-Token":csrfToken},body:JSON.stringify({muted})}),
  latestDiscovery: () => request<DiscoveryRun|null>("/api/v1/discovery/latest"),
  runDiscovery: (subnet:string, csrfToken:string) =>
    request<DiscoveryRun>("/api/v1/discovery/runs", { method:"POST", headers:{"X-CSRF-Token":csrfToken}, body:JSON.stringify({subnet}) }),
  addDiscoveredHost: (id:string, csrfToken:string) =>
    request<DiscoveredHost>(`/api/v1/discovery/hosts/${id}/add`, { method:"POST", headers:{"X-CSRF-Token":csrfToken} }),
  inspectDiscoveredHost: (id:string, csrfToken:string) =>
    request<DiscoveredHost>(`/api/v1/discovery/hosts/${id}/inspect`, { method:"POST", headers:{"X-CSRF-Token":csrfToken} }),
  networkChanges: () => request<NetworkChange[]>("/api/v1/discovery/changes"),
  vulnerabilities: () => request<VulnerabilityFinding[]>("/api/v1/vulnerabilities"),
  scanHostVulnerabilities: (id:string, csrfToken:string) => request<VulnerabilityFinding[]>(`/api/v1/vulnerabilities/hosts/${id}/scan`, {method:"POST",headers:{"X-CSRF-Token":csrfToken}}),
  updateFinding: (id:string,status:string,notes:string|null,csrfToken:string) => request<VulnerabilityFinding>(`/api/v1/vulnerabilities/${id}`, {method:"PUT",headers:{"X-CSRF-Token":csrfToken},body:JSON.stringify({status,user_notes:notes})}),
  storageTargets: () => request<StorageTarget[]>("/api/v1/storage/targets"),
  storageJobs: () => request<StorageScanJob[]>("/api/v1/storage/jobs"),
  createStorageTarget: (payload:Record<string,unknown>,csrfToken:string) => request<StorageTarget>("/api/v1/storage/targets",{method:"POST",headers:{"X-CSRF-Token":csrfToken},body:JSON.stringify(payload)}),
  scanStorageTarget: (id:string,csrfToken:string) => request<StorageScanJob>(`/api/v1/storage/targets/${id}/scan`,{method:"POST",headers:{"X-CSRF-Token":csrfToken}}),
  deleteStorageTarget: (id:string,csrfToken:string) => request<void>(`/api/v1/storage/targets/${id}`,{method:"DELETE",headers:{"X-CSRF-Token":csrfToken}}),
  overviewReport: () => request<OverviewReport>("/api/v1/reports/overview"),
  actionItems: () => request<ActionItem[]>("/api/v1/actions"),
  buildRemediationPlan: (findingId:string,csrfToken:string) => request<RemediationPlan>(`/api/v1/actions/${findingId}/plans`,{method:"POST",headers:{"X-CSRF-Token":csrfToken}}),
  approveRemediationPlan: (planId:string,csrfToken:string) => request<RemediationPlan>(`/api/v1/actions/plans/${planId}/approve`,{method:"POST",headers:{"X-CSRF-Token":csrfToken}}),
  releaseRemediationPlan: (planId:string,csrfToken:string) => request<RemediationPlan>(`/api/v1/actions/plans/${planId}/release`,{method:"POST",headers:{"X-CSRF-Token":csrfToken}}),
  cancelRemediationPlan: (planId:string,csrfToken:string) => request<RemediationPlan>(`/api/v1/actions/plans/${planId}/cancel`,{method:"POST",headers:{"X-CSRF-Token":csrfToken}}),
  retryRemediationPlan: (planId:string,csrfToken:string) => request<RemediationPlan>(`/api/v1/actions/plans/${planId}/retry`,{method:"POST",headers:{"X-CSRF-Token":csrfToken}}),
  archiveRemediationPlan: (planId:string,csrfToken:string) => request<RemediationPlan>(`/api/v1/actions/plans/${planId}/archive`,{method:"POST",headers:{"X-CSRF-Token":csrfToken}}),
  agents: () => request<Agent[]>("/api/v1/agents"),
  containers: () => request<ContainerInstance[]>("/api/v1/containers"),
  sources: () => request<InventorySource[]>("/api/v1/sources"),
  networkInventory: () => request<NetworkAsset[]>("/api/v1/sources/network-inventory"),
  networkActivity: () => request<NetworkIdentityEvent[]>("/api/v1/sources/network-activity"),
  linkNetworkIdentity: (observationIds:string[],deviceId:string|null,csrfToken:string) => request<void>("/api/v1/sources/network-inventory/link",{method:"POST",headers:{"X-CSRF-Token":csrfToken},body:JSON.stringify({observation_ids:observationIds,device_id:deviceId})}),
  createSource: (payload:Record<string,unknown>,csrfToken:string) => request<InventorySource>("/api/v1/sources",{method:"POST",headers:{"X-CSRF-Token":csrfToken},body:JSON.stringify(payload)}),
  syncSource: (id:string,csrfToken:string) => request<InventorySource>(`/api/v1/sources/${id}/sync`,{method:"POST",headers:{"X-CSRF-Token":csrfToken}}),
  sourceDevices: (id:string) => request<SourceDevice[]>(`/api/v1/sources/${id}/devices`),
  importSourceDevices: (id:string,ids:string[],csrfToken:string) => request<void>(`/api/v1/sources/${id}/import`,{method:"POST",headers:{"X-CSRF-Token":csrfToken},body:JSON.stringify({ids})}),
  deleteSource: (id:string,csrfToken:string) => request<void>(`/api/v1/sources/${id}`,{method:"DELETE",headers:{"X-CSRF-Token":csrfToken}}),
  createAgentEnrollment: (device_id:string,csrfToken:string) => request<AgentEnrollment>("/api/v1/agents/enrollments",{method:"POST",headers:{"X-CSRF-Token":csrfToken},body:JSON.stringify({device_id})}),
  deleteAgent: (id:string,csrfToken:string) => request<void>(`/api/v1/agents/${id}`,{method:"DELETE",headers:{"X-CSRF-Token":csrfToken}}),
  agentMetrics: (id:string) => request<AgentMetric[]>(`/api/v1/agents/${id}/metrics`),
  agentPackages: (id:string,search="") => request<InstalledPackage[]>(`/api/v1/agents/${id}/packages${search?`?search=${encodeURIComponent(search)}`:""}`),
  scanAgentPackages: (id:string,csrfToken:string) => request<VulnerabilityFinding[]>(`/api/v1/vulnerabilities/agents/${id}/scan`,{method:"POST",headers:{"X-CSRF-Token":csrfToken}}),
  health: () => request<{ status: string; dependencies: Record<string, { status: string }> }>("/api/v1/health/ready"),
  version: () => request<{ version: string; environment: string }>("/api/v1/version")
};
