import { getAccessToken, setAccessToken } from "./tokenManager";

async function refreshAccessToken(): Promise<boolean> {
  const basePath =
    import.meta.env.VITE_API_BASE_PATH || "http://localhost:8080";
  const refreshUrl = `${basePath}/api/v1/auth/refresh_token`;

  const response = await fetch(refreshUrl, {
    method: "GET",
    credentials: "include",
  });

  if (response.ok) {
    const data = await response.json();
    if (data.access_token) {
      setAccessToken(data.access_token);
      return true;
    }
  }
  return false;
}

export async function customFetch(
  input: RequestInfo,
  init?: RequestInit
): Promise<Response> {
  const headers = new Headers(init?.headers);
  const token = getAccessToken();
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  const options: RequestInit = {
    ...init,
    headers,
    credentials: "include",
  };

  let response = await fetch(input, options);
  if (response.status === 401) {
    const refreshed = await refreshAccessToken();
    if (refreshed) {
      const newToken = getAccessToken();
      if (newToken) {
        headers.set("Authorization", `Bearer ${newToken}`);
      }
      response = await fetch(input, { ...options, headers });
    }
  }
  return response;
}
