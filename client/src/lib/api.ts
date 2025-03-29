import { Configuration, AuthApi } from "../client-api";
import { getAccessToken, setAccessToken } from "./tokenManager";

const basePath: string =
  import.meta.env.VITE_API_BASE_PATH || "http://localhost:8080";

const configuration = new Configuration({
  basePath,
  apiKey: getOrRefreshAccessToken,
  baseOptions: {
    withCredentials: true,
  },
});

export const authApi = new AuthApi(configuration);

async function getOrRefreshAccessToken() {
  let token = getAccessToken();
  if (!token) {
    await refreshAccessToken();
    token = getAccessToken();
  }
  if (!token) {
    return "";
  }
  return `Bearer ${token}`;
}

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
      console.log("Refreshed access token");
      return true;
    }
  }
  return false;
}
