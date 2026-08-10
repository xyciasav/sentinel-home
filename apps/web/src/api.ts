export type User = { id: string; username: string; is_admin: boolean };
export type AuthResult = { user: User; csrf_token: string; expires_at: string };
export type Device = {
  id: string; display_name: string; address: string; hostname: string | null;
  device_type: string | null; criticality: string; trust: string; monitor_port: number | null;
  status: string; last_checked_at: string | null; last_latency_ms: number | null;
  last_failure_reason: string | null; notes: string | null;
};
export type ServiceMonitor = {
  id:string; name:string; group_name:string|null; target_scope:"internal"|"external"; url:string; device_id:string|null; expected_status:number;
  expected_text:string|null; timeout_seconds:number; verify_tls:boolean; enabled:boolean;
  severity:string; status:string; last_checked_at:string|null; last_success_at:string|null;
  outage_started_at:string|null; last_response_ms:number|null; last_status_code:number|null;
  last_failure_reason:string|null;
};

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
  health: () => request<{ status: string; dependencies: Record<string, { status: string }> }>("/api/v1/health/ready"),
  version: () => request<{ version: string; environment: string }>("/api/v1/version")
};
