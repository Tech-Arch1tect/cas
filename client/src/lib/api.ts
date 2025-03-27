import { BaseAPI, Configuration, AuthApi } from "../client-api";

const basePath = import.meta.env.VITE_API_BASE_PATH;

const configuration = new Configuration({
  basePath: basePath || "http://localhost:8080",
  credentials: "include",
});

export const api = new BaseAPI(configuration);
export const authApi = new AuthApi(configuration);
