import React, { createContext, useContext, useEffect, useState } from 'react';
import { api, User } from '../../services/api';
import {
  generateSharingKeyPair,
  exportKeyToJwk,
  importPrivateJwk,
} from '../../core/crypto/sharingKeyUtils';

interface AuthContextType {
  user: User | null;
  isLoading: boolean;
  login: (identifier: string, password: string) => Promise<void>;
  register: (username: string, email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  sharingPrivateKey: CryptoKey | null;
  ensureSharingKeypair: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [sharingPrivateKey, setSharingPrivateKey] = useState<CryptoKey | null>(null);

  useEffect(() => {
    async function checkAuth() {
      try {
        const { user: currentUser } = await api.getMe();
        setUser(currentUser);
      } catch {
        setUser(null);
      } finally {
        setIsLoading(false);
      }
    }
    checkAuth();
  }, []);

  const login = async (identifier: string, password: string) => {
    const res = await api.login(identifier, password);
    setUser(res.user);
    // Attempt to initialize or load sharing keypair
    await ensureSharingKeypair();
  };

  const register = async (username: string, email: string, password: string) => {
    const res = await api.register(username, email, password);
    setUser(res.user);
    await ensureSharingKeypair();
  };

  const logout = async () => {
    await api.logout();
    setUser(null);
    setSharingPrivateKey(null);
  };

  const ensureSharingKeypair = async () => {
    try {
      const existing = await api.getMyKeypair();
      if (existing) {
        // Load existing private key
        const privateJwk = JSON.parse(existing.encryptedPrivateKey) as JsonWebKey;
        const privKey = await importPrivateJwk(privateJwk);
        setSharingPrivateKey(privKey);
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
      }
    } catch {
      // Keypair initialization error handled gracefully
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isLoading,
        login,
        register,
        logout,
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
