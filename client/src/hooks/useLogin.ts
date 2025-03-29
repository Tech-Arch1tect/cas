import { useMutation } from "@tanstack/react-query";
import { authApi } from "../lib/api";
import { setAccessToken } from "../lib/tokenManager";

export const useLogin = () => {
  return useMutation({
    mutationFn: async ({
      username,
      password,
    }: {
      username: string;
      password: string;
    }) => {
      const res = await authApi.apiV1AuthLoginPost({
        username,
        password,
      });
      if (res.data.access_token) {
        setAccessToken(res.data.access_token);
      }
      return res;
    },
  });
};
