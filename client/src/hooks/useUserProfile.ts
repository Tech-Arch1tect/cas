import { useQuery } from "@tanstack/react-query";
import { authApi } from "../lib/api";

export const useUserProfile = () => {
  const {
    data: profile,
    error,
    isLoading,
  } = useQuery({
    queryKey: ["userProfile"],
    retry: false,
    queryFn: async () => {
      try {
        const profile = await authApi.apiV1AuthProfileGet();
        return profile.data.user;
      } catch (error) {
        throw new Error(
          (error as Error).message || "Failed to fetch user profile"
        );
      }
    },
  });

  return { profile, error, isLoading };
};
