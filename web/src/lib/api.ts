import { getRuntimeEnv } from "./env";

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
}

export interface InterfaceInfo {
  index: number;
  name: string;
}

export interface LoginResult {
  ip: string;
  username: string;
  mac: string | null;
}

export interface StatusResult {
  ip: string;
  online_user: string | null;
  online_mac: string | null;
}

export interface RandomLoginResult {
  mac: string;
  result: { Ok: LoginResult } | { Err: string };
}

export function isLoginOk(
  result: RandomLoginResult["result"]
): result is { Ok: LoginResult } {
  return "Ok" in result;
}

async function request<T>(
  path: string,
  options?: RequestInit
): Promise<ApiResponse<T>> {
  const { apiUrl, apiKey } = getRuntimeEnv();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options?.headers as Record<string, string>),
  };
  if (apiKey) {
    headers["X-API-Key"] = apiKey;
  }

  const res = await fetch(`${apiUrl}${path}`, {
    ...options,
    headers,
  });
  return res.json();
}

export async function getHealth() {
  return request<string>("/api/health");
}

export async function getInterfaces() {
  return request<InterfaceInfo[]>("/api/interfaces");
}

export async function getStatus(iface: string) {
  return request<StatusResult>(`/api/status?interface=${encodeURIComponent(iface)}`);
}

export async function getStatusMacvlan(parentInterface: string, macAddress: string) {
  return request<StatusResult>("/api/status/macvlan", {
    method: "POST",
    body: JSON.stringify({
      parent_interface: parentInterface,
      mac_address: macAddress,
    }),
  });
}

export async function loginLocal(
  iface: string,
  username?: string,
  password?: string,
  userinfoPath?: string,
) {
  return request<LoginResult>("/api/login/local", {
    method: "POST",
    body: JSON.stringify({
      interface: iface,
      ...(username && password ? { username, password } : {}),
      ...(userinfoPath ? { userinfo_path: userinfoPath } : {}),
    }),
  });
}

export async function logoutLocal(iface: string) {
  return request<void>("/api/logout/local", {
    method: "POST",
    body: JSON.stringify({ interface: iface }),
  });
}

export async function loginMacvlan(
  parentInterface: string,
  macAddress: string,
  username?: string,
  password?: string,
  userinfoPath?: string,
) {
  return request<LoginResult>("/api/login/macvlan", {
    method: "POST",
    body: JSON.stringify({
      parent_interface: parentInterface,
      mac_address: macAddress,
      ...(username && password ? { username, password } : {}),
      ...(userinfoPath ? { userinfo_path: userinfoPath } : {}),
    }),
  });
}

export async function logoutMacvlan(parentInterface: string, macAddress: string) {
  return request<void>("/api/logout/macvlan", {
    method: "POST",
    body: JSON.stringify({ parent_interface: parentInterface, mac_address: macAddress }),
  });
}

export async function loginRandom(
  parentInterface: string,
  count: number,
  userinfoPath?: string,
) {
  return request<RandomLoginResult[]>("/api/login/random", {
    method: "POST",
    body: JSON.stringify({
      parent_interface: parentInterface,
      count,
      ...(userinfoPath ? { userinfo_path: userinfoPath } : {}),
    }),
  });
}
