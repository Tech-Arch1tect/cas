import React, { createContext, useContext, useEffect, useState } from "react";
import { useUserProfile } from "../hooks/useUserProfile";
import { useLogin } from "../hooks/useLogin";
import { useRegister } from "../hooks/useRegister";
import { useLogout } from "../hooks/useLogout";
import { useQueryClient } from "@tanstack/react-query";

interface AuthContextType {
  user: any;
  loading: boolean;
  isAuthenticated: boolean;
  login: (credentials: { username: string; password: string }) => Promise<void>;
  register: (data: {
    email: string;
    username: string;
    password: string;
  }) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider = ({ children }: { children: React.ReactNode }) => {
  const [user, setUser] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const { profile, isLoading } = useUserProfile();
  const loginMutation = useLogin();
  const registerMutation = useRegister();
  const logoutMutation = useLogout();
  const queryClient = useQueryClient();

  useEffect(() => {
    if (!isLoading) {
      setUser(profile);
      setLoading(false);
    }
  }, [profile, isLoading]);

  const login = async (credentials: { username: string; password: string }) => {
    await loginMutation.mutateAsync(credentials);
    await queryClient.invalidateQueries({ queryKey: ["userProfile"] });
  };

  const register = async (data: {
    email: string;
    username: string;
    password: string;
  }) => {
    await registerMutation.mutateAsync(data);
    await queryClient.invalidateQueries({ queryKey: ["userProfile"] });
  };

  const logout = async () => {
    await logoutMutation.mutateAsync();
    setUser(null);
    await queryClient.invalidateQueries({ queryKey: ["userProfile"] });
  };

  if (loading) {
    return <div>Loading...</div>;
  }

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        isAuthenticated: !!user,
        login,
        register,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};
