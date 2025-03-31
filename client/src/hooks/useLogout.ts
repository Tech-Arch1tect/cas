import { useMutation, useQueryClient } from "@tanstack/react-query";
import { authApi } from "../lib/api";
import { setAccessToken } from "../lib/tokenManager";

export const useLogout = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async () => {
      try {
        const res = await authApi.apiV1AuthLogoutPost();
        setAccessToken("");
        return res;
      } catch (error) {
        setAccessToken("");
        throw error;
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["userProfile"] });
    },
  });
};
