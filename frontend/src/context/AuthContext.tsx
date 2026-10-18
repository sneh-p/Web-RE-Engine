import React, { createContext, useContext, useEffect, useState, useCallback } from 'react';
import { fetchAuthMe, loginAdmin, logoutAdmin, setOnUnauthorized } from '../api/client';

interface AuthContextType {
  authenticated: boolean | null;
  authConfigured: boolean;
  loading: boolean;
  login: (password: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshAuth: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType>({
  authenticated: null,
  authConfigured: true,
  loading: true,
  login: async () => {},
  logout: async () => {},
  refreshAuth: async () => {},
});

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [authenticated, setAuthenticated] = useState<boolean | null>(null);
  const [authConfigured, setAuthConfigured] = useState<boolean>(true);
  const [loading, setLoading] = useState<boolean>(true);

  const refreshAuth = useCallback(async () => {
    try {
      const info = await fetchAuthMe();
      setAuthenticated(info.authenticated);
      setAuthConfigured(info.authConfigured);
    } catch {
      setAuthenticated(false);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshAuth();
    setOnUnauthorized(() => {
      setAuthenticated(false);
    });
  }, [refreshAuth]);

  const login = async (password: string) => {
    await loginAdmin(password);
    await refreshAuth();
  };

  const logout = async () => {
    await logoutAdmin();
    setAuthenticated(false);
  };

  return (
    <AuthContext.Provider
      value={{
        authenticated,
        authConfigured,
        loading,
        login,
        logout,
        refreshAuth,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth() {
  return useContext(AuthContext);
}
