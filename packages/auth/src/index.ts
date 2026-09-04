export type Auth2CIdentity = {
  userId: string;
  token: string;
  email: string | null;
  name: string | null;
  picture: string | null;
  expiresAt: number;
};
export type SignInOptions = { requestProfile?: boolean; returnTo?: string; redirectUri?: string };
/**
 * Auth2C browser client.
 *
 * `signOut` is async: it attempts /session/revoke, clears the local identity in
 * a finally block, emits auth2c:change, and resolves after the remote attempt
 * (success or failure). Decoded browser claims are display-only; authoritative
 * revocation requires /session/check on the server.
 */
export type Auth2CClient = {
  signIn(o?: SignInOptions): Promise<void>;
  handleCallback(): Promise<Auth2CIdentity | null>;
  getIdentity(): Auth2CIdentity | null;
  signOut(): Promise<void>;
  checkSession(): Promise<boolean>;
};
declare global {
  interface Window {
    Auth2C: Auth2CClient;
  }
}
export const getAuth2C = () => {
  if (typeof window === "undefined" || !window.Auth2C) throw Error("Load the Auth2C browser script first");
  return window.Auth2C;
};
