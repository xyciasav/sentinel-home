export type User = { id: string; username: string; is_admin: boolean };
export type AuthResult = { user: User; csrf_token: string; expires_at: string };

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(path, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...options.headers },
    ...options
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({ detail: "Request failed" }));
    throw new Error(body.detail ?? `Request failed (${response.status})`);
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
  health: () => request<{ status: string; dependencies: Record<string, { status: string }> }>("/api/v1/health/ready"),
  version: () => request<{ version: string; environment: string }>("/api/v1/version")
};
