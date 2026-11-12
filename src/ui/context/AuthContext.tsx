import React, { createContext, useContext, useEffect, useState } from 'react';
import { api, User } from '../../services/api';
import {
  generateSharingKeyPair,
  exportKeyToJwk,
  importPrivateJwk,
} from '../../core/crypto/sharingKeyUtils';

export type AuthState = 'loading' | 'authenticated' | 'unauthenticated';

export interface LogoutResult {
  success: boolean;
  serverInvalidated: boolean;
  error?: string;
}

interface AuthContextType {
  user: User | null;
  authState: AuthState;
  isLoading: boolean;
  isLoggingOut: boolean;
  sessionEpoch: number;
  logoutNotice: string | null;
  clearLogoutNotice: () => void;
  login: (identifier: string, password: string) => Promise<void>;
  register: (username: string, email: string, password: string) => Promise<void>;
  logout: () => Promise<LogoutResult>;
  teardownSession: (notice?: string | null) => void;
  sharingPrivateKey: CryptoKey | null;
  ensureSharingKeypair: () => Promise<CryptoKey | null>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [authState, setAuthState] = useState<AuthState>('loading');
  const [isLoggingOut, setIsLoggingOut] = useState<boolean>(false);
  const [sessionEpoch, setSessionEpoch] = useState<number>(0);
  const [logoutNotice, setLogoutNotice] = useState<string | null>(null);
  const [sharingPrivateKey, setSharingPrivateKey] = useState<CryptoKey | null>(null);

  const userRef = React.useRef<User | null>(null);
  userRef.current = user;

  const authOpIdRef = React.useRef<number>(0);

  const teardownSession = (notice?: string | null) => {
    setUser(null);
    setAuthState('unauthenticated');
    setSharingPrivateKey(null);
    setSessionEpoch((prev) => prev + 1);
    api.setCsrfToken(null);
    api.cancelPendingRequests();
    if (notice !== undefined) {
      setLogoutNotice(notice);
    }
  };

  const ensureSharingKeypair = async (): Promise<CryptoKey | null> => {
    try {
      const existing = await api.getMyKeypair();
      if (existing) {
        // Load existing private key
        const privateJwk = JSON.parse(existing.encryptedPrivateKey) as JsonWebKey;
        const privKey = await importPrivateJwk(privateJwk);
        setSharingPrivateKey(privKey);
        return privKey;
      } else {
        // Generate new keypair
        const pair = await generateSharingKeyPair();
        const publicJwk = await exportKeyToJwk(pair.publicKey);
        const privateJwk = await exportKeyToJwk(pair.privateKey);

        await api.saveSharingKeypair({
          publicKeyJwk: publicJwk,
          encryptedPrivateKey: JSON.stringify(privateJwk),
        });

        setSharingPrivateKey(pair.privateKey);
        return pair.privateKey;
      }
    } catch {
      return null;
    }
  };

  useEffect(() => {
    // Listen for unauthorized 401s from expired sessions only when a user was authenticated
    api.onUnauthorized(() => {
      if (userRef.current) {
        teardownSession('Your session has expired. You have been signed out.');
      }
    });

    async function checkAuth() {
      const opId = ++authOpIdRef.current;
      try {
        const { user: currentUser } = await api.getMe();
        if (opId !== authOpIdRef.current) return; // Discard stale response
        if (currentUser) {
          setUser(currentUser);
          setAuthState('authenticated');
          await ensureSharingKeypair();
        } else {
          setUser(null);
          setAuthState('unauthenticated');
        }
      } catch {
        if (opId !== authOpIdRef.current) return;
        setUser(null);
        setAuthState('unauthenticated');
      }
    }
    checkAuth();
  }, []);

  const login = async (identifier: string, password: string) => {
    const opId = ++authOpIdRef.current;

    // If an account was previously logged in, tear down previous account state first
    if (userRef.current) {
      teardownSession(null);
    }

    const res = await api.login(identifier, password);
    if (opId !== authOpIdRef.current) return; // Stale request, discard

    setUser(res.user);
    setAuthState('authenticated');
    setSessionEpoch((prev) => prev + 1);
    await ensureSharingKeypair();
  };

  const register = async (username: string, email: string, password: string) => {
    const opId = ++authOpIdRef.current;

    if (userRef.current) {
      teardownSession(null);
    }

    const res = await api.register(username, email, password);
    if (opId !== authOpIdRef.current) return;

    setUser(res.user);
    setAuthState('authenticated');
    setSessionEpoch((prev) => prev + 1);
    await ensureSharingKeypair();
  };

  const logout = async (): Promise<LogoutResult> => {
    ++authOpIdRef.current;
    setIsLoggingOut(true);
    let serverInvalidated = false;
    let errorMsg: string | undefined;

    try {
      await api.logout();
      serverInvalidated = true;
    } catch (err) {
      errorMsg = err instanceof Error ? err.message : 'Server session revocation failed';
    } finally {
      // Fail-closed on the client: always clear client authentication and session state immediately
      teardownSession(
        errorMsg ? 'Signed out locally. Server could not be contacted to invalidate remote session.' : null
      );
      setIsLoggingOut(false);
    }

    return {
      success: true,
      serverInvalidated,
      error: errorMsg,
    };
  };

  const clearLogoutNotice = () => {
    setLogoutNotice(null);
  };

  const isLoading = authState === 'loading';

  return (
    <AuthContext.Provider
      value={{
        user,
        authState,
        isLoading,
        isLoggingOut,
        sessionEpoch,
        logoutNotice,
        clearLogoutNotice,
        login,
        register,
        logout,
        teardownSession,
        sharingPrivateKey,
        ensureSharingKeypair,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth(): AuthContextType {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within an AuthProvider');
  return ctx;
}
