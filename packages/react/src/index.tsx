import { useCallback, useEffect, useState } from "react";
import { getAuth2C, type Auth2CIdentity, type SignInOptions } from "@auth2c/auth";
export function useAuth2C() {
  const [identity, setIdentity] = useState<Auth2CIdentity | null>(null),
    [loading, setLoading] = useState(true);
  useEffect(() => {
    const a = getAuth2C(),
      sync = () => setIdentity(a.getIdentity());
    sync();
    a.handleCallback()
      .then(sync)
      .finally(() => setLoading(false));
    addEventListener("auth2c:change", sync);
    return () => removeEventListener("auth2c:change", sync);
  }, []);
  return {
    identity,
    loading,
    signIn: useCallback((o?: SignInOptions) => getAuth2C().signIn(o), []),
    signOut: useCallback(() => getAuth2C().signOut(), []),
    checkSession: useCallback(() => getAuth2C().checkSession(), []),
  };
}
export function createAuth2CConvex() {
  const signIn = (o?: SignInOptions) => getAuth2C().signIn(o),
    signOut = () => getAuth2C().signOut();
  return {
    signIn,
    signOut,
    useAuth() {
      const { identity, loading } = useAuth2C();
      return {
        isLoading: loading,
        isAuthenticated: !!identity,
        fetchAccessToken: useCallback(async () => getAuth2C().getIdentity()?.token ?? null, []),
      };
    },
  };
}
