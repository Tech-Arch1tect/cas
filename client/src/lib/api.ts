import { BaseAPI, Configuration, AuthApi } from "../client-api";
import { customFetch } from "./customFetch";

const basePath: string =
  import.meta.env.VITE_API_BASE_PATH || "http://localhost:8080";

const configuration = new Configuration({
  basePath,
  credentials: "include",
  fetchApi: customFetch,
});

export const api = new BaseAPI(configuration);
export const authApi = new AuthApi(configuration);
