import React, { useState } from 'react';
import { Lock, Unlock, Shield, HardDrive, LogIn, LogOut, User as UserIcon } from 'lucide-react';
import { EncryptPanel } from './ui/components/EncryptPanel';
import { DecryptPanel } from './ui/components/DecryptPanel';
import { VaultPanel } from './ui/components/VaultPanel';
import { AuthModal } from './ui/components/AuthModal';
import { AuthProvider, useAuth } from './ui/context/AuthContext';

type ActiveView = 'workspace' | 'vault';
type WorkspaceMode = 'encrypt' | 'decrypt' | 'split';

const AppContent: React.FC = () => {
  const [activeView, setActiveView] = useState<ActiveView>('workspace');
  const [workspaceMode, setWorkspaceMode] = useState<WorkspaceMode>('split');
  const [showAuthModal, setShowAuthModal] = useState<boolean>(false);

  const { user, logout } = useAuth();

  return (
    <div className="app-container">
      {/* Subtle Lava-Lamp Ambient Background Blobs */}
      <div className="lava-lamp-bg" aria-hidden="true">
        <div className="blob blob-1" />
        <div className="blob blob-2" />
        <div className="blob blob-3" />
      </div>

      <header className="app-header" role="banner">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
          <div className="brand-row">
            <Shield size={28} aria-hidden="true" color="var(--border-focus)" />
            <h1 className="brand-title">SecureBox</h1>
            <span className="brand-badge">Security-First Vault</span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            {user ? (
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span style={{ fontSize: '0.875rem', fontWeight: 500, color: 'var(--text-secondary)' }}>
                  <UserIcon size={14} style={{ display: 'inline', verticalAlign: 'middle', marginRight: '4px' }} />
                  {user.username}
                </span>
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={logout}
                  title="Sign out of account"
                >
                  <LogOut size={14} aria-hidden="true" />
                  <span>Logout</span>
                </button>
              </div>
            ) : (
              <button
                type="button"
                className="btn btn-primary btn-sm"
                onClick={() => setShowAuthModal(true)}
              >
                <LogIn size={14} aria-hidden="true" />
                <span>Sign In / Register</span>
              </button>
            )}
          </div>
        </div>

        <p className="app-description">
          Client-side authenticated AES-256-GCM encryption, zero-knowledge private document vault, and recipient-bound key sharing.
        </p>

        {/* Primary View Switcher: Document Workspace vs Private Vault */}
        <nav className="view-switcher" role="tablist" style={{ marginTop: '20px', display: 'flex', gap: '8px' }}>
          <button
            type="button"
            role="tab"
            aria-selected={activeView === 'workspace'}
            className={`tab-btn ${activeView === 'workspace' ? 'active' : ''}`}
            onClick={() => setActiveView('workspace')}
            style={{ borderBottom: activeView === 'workspace' ? '2px solid var(--text-primary)' : '2px solid transparent' }}
          >
            <Lock size={15} aria-hidden="true" />
            <span>Encrypt / Decrypt Workspace</span>
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={activeView === 'vault'}
            className={`tab-btn ${activeView === 'vault' ? 'active' : ''}`}
            onClick={() => {
              if (!user) {
                setShowAuthModal(true);
              } else {
                setActiveView('vault');
              }
            }}
            style={{ borderBottom: activeView === 'vault' ? '2px solid var(--text-primary)' : '2px solid transparent' }}
          >
            <HardDrive size={15} aria-hidden="true" />
            <span>Private Document Vault {user ? '' : '(Login Required)'}</span>
          </button>
        </nav>
      </header>

      <main role="main">
        {activeView === 'workspace' && (
          <div>
            {/* Workspace mode switcher */}
            <div className="workspace-controls">
              <div className="workspace-toggle-group" role="tablist" aria-label="Document workspace views">
                <button
                  type="button"
                  role="tab"
                  aria-selected={workspaceMode === 'split'}
                  className={`workspace-tab-btn ${workspaceMode === 'split' ? 'active' : ''}`}
                  onClick={() => setWorkspaceMode('split')}
                >
                  <span>Side-by-Side</span>
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={workspaceMode === 'encrypt'}
                  className={`workspace-tab-btn ${workspaceMode === 'encrypt' ? 'active' : ''}`}
                  onClick={() => setWorkspaceMode('encrypt')}
                >
                  <Lock size={15} aria-hidden="true" />
                  <span>Encrypt</span>
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={workspaceMode === 'decrypt'}
                  className={`workspace-tab-btn ${workspaceMode === 'decrypt' ? 'active' : ''}`}
                  onClick={() => setWorkspaceMode('decrypt')}
                >
                  <Unlock size={15} aria-hidden="true" />
                  <span>Decrypt</span>
                </button>
              </div>
            </div>

            {/* Responsive Document Workspace Grid */}
            <div className={`workspace-grid ${workspaceMode}`}>
              {(workspaceMode === 'split' || workspaceMode === 'encrypt') && (
                <div className="workspace-col">
                  <EncryptPanel />
                </div>
              )}
              {(workspaceMode === 'split' || workspaceMode === 'decrypt') && (
                <div className="workspace-col">
                  <DecryptPanel />
                </div>
              )}
            </div>
          </div>
        )}

        {activeView === 'vault' && (
          <div>
            {user ? (
              <VaultPanel />
            ) : (
              <div className="panel-card" style={{ textAlign: 'center', padding: '48px 16px' }}>
                <Shield size={40} style={{ margin: '0 auto 16px', color: 'var(--border-focus)' }} />
                <h2 style={{ fontSize: '1.25rem', marginBottom: '8px' }}>Authentication Required</h2>
                <p style={{ color: 'var(--text-secondary)', marginBottom: '20px' }}>
                  Please sign in to access your private encrypted document vault and shared documents.
                </p>
                <button type="button" className="btn btn-primary" onClick={() => setShowAuthModal(true)}>
                  <LogIn size={16} aria-hidden="true" />
                  <span>Sign In or Register</span>
                </button>
              </div>
            )}
          </div>
        )}
      </main>

      {/* Auth Modal */}
      {showAuthModal && (
        <div className="modal-backdrop" onClick={() => setShowAuthModal(false)}>
          <div onClick={(e) => e.stopPropagation()} style={{ width: '100%', maxWidth: '440px' }}>
            <AuthModal onClose={() => setShowAuthModal(false)} />
          </div>
        </div>
      )}

      <footer className="app-footer" role="contentinfo">
        <p>
          <strong>Security Guarantee:</strong> Client-side end-to-end encryption (E2EE) powered by the native Web Crypto API (AES-256-GCM, SHA-256, ECDH P-256). Stored documents remain encrypted at all times on the server. Decryption keys never transit in plaintext.
        </p>
        <p style={{ marginTop: '6px' }}>
          <strong>Notice:</strong> Document encryption requires safe retention of your 256-bit key. SecureBox cannot recover encrypted files if the key is lost.
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
