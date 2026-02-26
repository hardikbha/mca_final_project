import { useCallback, useEffect, useState } from "react";
import type { UserInfo } from "../types";
import * as api from "../services/api";

export function useAuth() {
  const [token, setToken] = useState<string>(() => localStorage.getItem("access_token") ?? "");
  const [currentUser, setCurrentUser] = useState<UserInfo | null>(null);

  const saveToken = useCallback((t: string) => {
    localStorage.setItem("access_token", t);
    setToken(t);
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem("access_token");
    setToken("");
    setCurrentUser(null);
  }, []);

  const login = useCallback(
    async (identifier: string, password: string): Promise<string | null> => {
      const result = await api.login(identifier, password);
      if (result.error || !result.data) return result.error ?? "Login failed.";
      saveToken(result.data.access_token);
      setCurrentUser(result.data.user);
      return null;
    },
    [saveToken]
  );

  const register = useCallback(
    async (data: { full_name: string; email: string; phone: string; password: string }): Promise<string | null> => {
      const result = await api.register(data);
      if (result.error || !result.data) return result.error ?? "Registration failed.";
      saveToken(result.data.access_token);
      setCurrentUser(result.data.user);
      return null;
    },
    [saveToken]
  );

  // Fetch user info on mount if token exists
  useEffect(() => {
    if (!token) return;
    fetch(`${api.API_BASE}/api/v1/auth/me`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (data) setCurrentUser(data as UserInfo);
        else logout();
      })
      .catch(() => logout());
  }, [token, logout]);

  return { token, currentUser, login, register, logout, isLoggedIn: !!token };
}
