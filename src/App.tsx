import React, { useState } from 'react';
import { Lock, Unlock, Shield, HardDrive, LogOut, UserPlus } from 'lucide-react';
import { EncryptPanel } from './ui/components/EncryptPanel';
import { DecryptPanel } from './ui/components/DecryptPanel';
import { VaultPanel } from './ui/components/VaultPanel';
import { AuthModal } from './ui/components/AuthModal';
import { AuthProvider, useAuth } from './ui/context/AuthContext';

type ActiveTab = 'encrypt' | 'decrypt' | 'vault';

const AppContent: React.FC = () => {
  const [activeTab, setActiveTab] = useState<ActiveTab>('encrypt');
  const [showAuthModal, setShowAuthModal] = useState<boolean>(false);
  const [authModalMode, setAuthModalMode] = useState<'login' | 'register'>('register');

  const { user, logout } = useAuth();

  const handleOpenAuth = (mode: 'login' | 'register') => {
    setAuthModalMode(mode);
    setShowAuthModal(true);
  };

  const handleTabClick = (tab: ActiveTab) => {
    if (tab === 'vault') {
      if (!user) {
        // Prompt requirement: redirect to register for unauthenticated users, or login
        handleOpenAuth('register');
        return;
      }
    }
    setActiveTab(tab);
  };

  return (
    <div className="app-container">
      {/* Subtle Lava-Lamp Ambient Background Blobs (GPU/CPU optimized) */}
      <div className="lava-lamp-bg" aria-hidden="true">
        <div className="blob blob-1" />
        <div className="blob blob-2" />
        <div className="blob blob-3" />
        <div className="blob blob-4" />
      </div>

      <header className="app-header" role="banner">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
          {/* Top Left: Brand and (if logged in) User Profile */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
            <div className="brand-row">
              <Shield size={28} aria-hidden="true" color="var(--border-focus)" />
              <h1 className="brand-title">SecureBox</h1>
              <span className="brand-badge">Client-Side Only</span>
            </div>

            {user && (
              <div
                className="user-profile-badge"
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '8px',
                  padding: '4px 12px',
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '9999px',
                  boxShadow: 'var(--shadow-card)',
                }}
              >
                <div
                  style={{
                    width: '24px',
                    height: '24px',
                    borderRadius: '50%',
                    background: 'var(--border-focus)',
                    color: '#fff',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: '0.75rem',
                    fontWeight: 700,
                  }}
                >
                  {user.username.charAt(0).toUpperCase()}
                </div>
                <span style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                  {user.username}
                </span>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>({user.email})</span>
              </div>
            )}
          </div>

          {/* Top Right: Register (if unauthenticated) or Log Out (dynamic button if logged in) */}
          <div>
            {user ? (
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={async () => {
                  await logout();
                  if (activeTab === 'vault') setActiveTab('encrypt');
                }}
                title="Log Out of your account"
              >
                <LogOut size={15} aria-hidden="true" />
                <span>Log Out</span>
              </button>
            ) : (
              <div style={{ display: 'flex', gap: '8px' }}>
                <button
                  type="button"
                  className="btn btn-primary btn-sm"
                  onClick={() => handleOpenAuth('register')}
                >
                  <UserPlus size={15} aria-hidden="true" />
                  <span>Register</span>
                </button>
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={() => handleOpenAuth('login')}
                >
                  <span>Sign In</span>
                </button>
              </div>
            )}
          </div>
        </div>

        <p className="app-description">
          Local document encryption and cryptographic protection. Plaintext and keys never leave your device.
        </p>
      </header>

      <main role="main">
        {/* Navigation Tabs: Encrypt / Decrypt / Private Document Vault */}
        <nav className="tabs-nav" role="tablist" aria-label="Document protection operations">
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'encrypt'}
            aria-controls="panel-encrypt"
            id="tab-encrypt"
            className="tab-btn"
            onClick={() => handleTabClick('encrypt')}
          >
            <Lock size={16} aria-hidden="true" />
            <span>Encrypt</span>
          </button>

          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'decrypt'}
            aria-controls="panel-decrypt"
            id="tab-decrypt"
            className="tab-btn"
            onClick={() => handleTabClick('decrypt')}
          >
            <Unlock size={16} aria-hidden="true" />
            <span>Decrypt</span>
          </button>

          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'vault'}
            aria-controls="panel-vault"
            id="tab-vault"
            className="tab-btn"
            onClick={() => handleTabClick('vault')}
          >
            <HardDrive size={16} aria-hidden="true" />
            <span>Private Document Vault {!user && <span style={{ fontSize: '0.75rem', opacity: 0.7 }}>(Account Required)</span>}</span>
          </button>
        </nav>

        {/* Tab Panels */}
        <section
          id={`panel-${activeTab}`}
          role="tabpanel"
          aria-labelledby={`tab-${activeTab}`}
        >
          {activeTab === 'encrypt' && (
            <EncryptPanel onRequireRegister={() => handleOpenAuth('register')} />
          )}
          {activeTab === 'decrypt' && (
            <DecryptPanel />
          )}
          {activeTab === 'vault' && user && (
            <VaultPanel />
          )}
        </section>
      </main>

      {/* Auth Modal */}
      {showAuthModal && (
        <div className="modal-backdrop" onClick={() => setShowAuthModal(false)}>
          <div onClick={(e) => e.stopPropagation()} style={{ width: '100%', maxWidth: '440px' }}>
            <AuthModal
              initialMode={authModalMode}
              onClose={() => {
                setShowAuthModal(false);
              }}
            />
          </div>
        </div>
      )}

      <footer className="app-footer" role="contentinfo">
        <p>
          <strong>Security Guarantee:</strong> All operations run locally inside your browser via the native Web Crypto API (AES-256-GCM and SHA-256). Stored vault documents remain encrypted at all times on the server.
        </p>
        <p style={{ marginTop: '6px' }}>
          <strong>Notice:</strong> Document encryption requires safe retention of your 256-bit key. SecureBox cannot recover files if the key is lost.
        </p>
      </footer>
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
};

export default App;
