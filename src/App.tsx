import React, { useState } from 'react';
import {
  Lock,
  Unlock,
  HardDrive,
  LogOut,
  UserPlus,
  Search,
  Bell,
  Wallet,
  FileText,
  ChevronDown,
  LayoutGrid,
  ShieldCheck,
} from 'lucide-react';
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
  const [dashboardOpen, setDashboardOpen] = useState<boolean>(true);

  const { user, logout } = useAuth();

  const handleOpenAuth = (mode: 'login' | 'register') => {
    setAuthModalMode(mode);
    setShowAuthModal(true);
  };

  const handleTabClick = (tab: ActiveTab) => {
    if (tab === 'vault') {
      if (!user) {
        handleOpenAuth('register');
        return;
      }
    }
    setActiveTab(tab);
  };

  return (
    <div className="app-viewport">
      {/* Subtle Lava-Lamp Ambient Background Blobs (GPU/CPU optimized) */}
      <div className="lava-lamp-bg" aria-hidden="true">
        <div className="blob blob-1" />
        <div className="blob blob-2" />
        <div className="blob blob-3" />
        <div className="blob blob-4" />
      </div>

      {/* Main Glass Window Shell (matching reference screenshot) */}
      <div className="glass-window">
        {/* Leftmost slim icon rail */}
        <aside className="icon-rail" aria-label="Quick Switcher">
          <div
            className="rail-avatar"
            title={user ? `${user.username} (${user.email})` : 'Guest User'}
          >
            {user ? (
              user.username.charAt(0).toUpperCase()
            ) : (
              <span style={{ fontSize: '0.85rem' }}>SB</span>
            )}
          </div>

          <div className="sidebar-section-title" style={{ fontSize: '0.625rem', marginTop: '8px' }}>MAIN</div>

          <button
            type="button"
            className={`rail-btn ${activeTab === 'encrypt' ? 'active' : ''}`}
            onClick={() => handleTabClick('encrypt')}
            title="Encrypt Documents"
          >
            <LayoutGrid size={20} />
          </button>

          <button
            type="button"
            className={`rail-btn ${activeTab === 'decrypt' ? 'active' : ''}`}
            onClick={() => handleTabClick('decrypt')}
            title="Decrypt Documents"
          >
            <Unlock size={20} />
          </button>

          <button
            type="button"
            className={`rail-btn ${activeTab === 'vault' ? 'active' : ''}`}
            onClick={() => handleTabClick('vault')}
            title="Private Document Vault"
          >
            <HardDrive size={20} />
          </button>

          <button
            type="button"
            className="rail-btn"
            title="Cryptographic Wallet / Key Storage"
          >
            <Wallet size={20} />
          </button>

          <button
            type="button"
            className="rail-btn"
            title="Security Notifications"
          >
            <Bell size={20} />
          </button>

          <div className="rail-divider" />

          <div className="sidebar-section-title" style={{ fontSize: '0.625rem' }}>COLLAB</div>

          {/* Collaborator Avatars from reference UI */}
          <div
            className="rail-collaborator-dot"
            style={{ background: '#38bdf8' }}
            title="Collaborator: Alice"
          >
            A
          </div>
          <div
            className="rail-collaborator-dot"
            style={{ background: '#ec4899' }}
            title="Collaborator: Bob"
          >
            B
          </div>
          <div
            className="rail-collaborator-dot"
            style={{ background: '#8b5cf6' }}
            title="Collaborator: Carol"
          >
            C
          </div>
        </aside>

        {/* Sidebar Navigation */}
        <aside className="glass-sidebar" aria-label="Main Navigation">
          <div className="sidebar-logo">
            <div className="logo-graphic">
              {/* Reference UI 3-bar cyan & blue logo style */}
              <svg width="34" height="34" viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">
                <rect x="6" y="14" width="7" height="18" rx="3.5" fill="#38bdf8" />
                <rect x="17" y="6" width="7" height="26" rx="3.5" fill="#1d72fe" />
                <rect x="28" y="10" width="7" height="14" rx="3.5" fill="#60a5fa" />
              </svg>
            </div>
            <div>
              <div style={{ fontSize: '1.15rem', fontWeight: 800, color: 'var(--sb-text)', letterSpacing: '-0.02em', lineHeight: 1.1 }}>
                SecureBox
              </div>
              <div style={{ fontSize: '0.6875rem', fontWeight: 600, color: 'var(--sb-primary)' }}>
                Client-Side Encryption
              </div>
            </div>
          </div>

          <div>
            <div className="sidebar-section-title">MAIN</div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <div>
                <button
                  type="button"
                  className={`sidebar-nav-item ${activeTab === 'encrypt' ? 'active' : ''}`}
                  onClick={() => setDashboardOpen(!dashboardOpen)}
                >
                  <span style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <LayoutGrid size={17} color="var(--sb-primary)" />
                    <span>Workspace</span>
                  </span>
                  <ChevronDown
                    size={16}
                    style={{
                      transform: dashboardOpen ? 'rotate(180deg)' : 'rotate(0deg)',
                      transition: 'transform 0.2s ease',
                      color: 'var(--sb-text-muted)',
                    }}
                  />
                </button>

                {dashboardOpen && (
                  <div className="sidebar-subnav">
                    <button
                      type="button"
                      className={`sidebar-subitem ${activeTab === 'encrypt' ? 'active' : ''}`}
                      onClick={() => handleTabClick('encrypt')}
                    >
                      Encrypt
                    </button>
                    <button
                      type="button"
                      className={`sidebar-subitem ${activeTab === 'decrypt' ? 'active' : ''}`}
                      onClick={() => handleTabClick('decrypt')}
                    >
                      Decrypt
                    </button>
                    <button
                      type="button"
                      className={`sidebar-subitem ${activeTab === 'vault' ? 'active' : ''}`}
                      onClick={() => handleTabClick('vault')}
                    >
                      Private Document Vault
                    </button>
                  </div>
                )}
              </div>

              <button
                type="button"
                className={`sidebar-nav-item ${activeTab === 'vault' ? 'active' : ''}`}
                onClick={() => handleTabClick('vault')}
              >
                <span style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <HardDrive size={17} />
                  <span>Vault</span>
                </span>
                <span className="sidebar-badge">E2EE</span>
              </button>

              <button
                type="button"
                className="sidebar-nav-item"
                onClick={() => handleTabClick('encrypt')}
              >
                <span style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <FileText size={17} />
                  <span>Libraries</span>
                </span>
              </button>

              <button
                type="button"
                className="sidebar-nav-item"
                onClick={() => handleTabClick('vault')}
              >
                <span style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <ShieldCheck size={17} />
                  <span>Saved Keys</span>
                </span>
              </button>
            </div>
          </div>

          <div style={{ marginTop: 'auto' }}>
            <div className="sidebar-section-title">USER SESSION</div>
            {user ? (
              <div style={{ background: 'rgba(255, 255, 255, 0.7)', padding: '12px', borderRadius: 'var(--sb-radius-sm)', border: '1px solid var(--sb-border-subtle)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                  <div
                    style={{
                      width: '26px',
                      height: '26px',
                      borderRadius: '50%',
                      background: 'var(--sb-primary)',
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
                  <div style={{ overflow: 'hidden' }}>
                    <div style={{ fontSize: '0.8125rem', fontWeight: 700, color: 'var(--sb-text)', textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'now1wrap' }}>
                      {user.username}
                    </div>
                    <div style={{ fontSize: '0.6875rem', color: 'var(--sb-text-muted)', textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>
                      {user.email}
                    </div>
                  </div>
                </div>
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  style={{ width: '100%' }}
                  onClick={async () => {
                    await logout();
                    if (activeTab === 'vault') setActiveTab('encrypt');
                  }}
                >
                  <LogOut size={14} aria-hidden="true" />
                  <span>Log Out</span>
                </button>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <button
                  type="button"
                  className="btn btn-primary btn-sm"
                  onClick={() => handleOpenAuth('register')}
                >
                  <UserPlus size={14} aria-hidden="true" />
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
        </aside>

        {/* Main Content Pane */}
        <main className="glass-main" role="main">
          {/* Top Bar with Search and Auth Actions */}
          <div className="main-topbar">
            <div className="search-pill-box">
              <Search size={16} aria-hidden="true" />
              <input
                type="text"
                placeholder="Search..."
                className="search-pill-input"
                aria-label="Search documents and keys"
              />
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              {/* Tabs: Encrypt / Decrypt / Private Document Vault */}
              <nav className="tabs-nav" style={{ margin: 0, border: 'none', gap: '4px' }} role="tablist">
                <button
                  type="button"
                  role="tab"
                  aria-selected={activeTab === 'encrypt'}
                  className="tab-btn"
                  style={{
                    borderRadius: 'var(--sb-radius-pill)',
                    padding: '8px 16px',
                    border: activeTab === 'encrypt' ? '1px solid var(--sb-border)' : '1px solid transparent',
                  }}
                  onClick={() => handleTabClick('encrypt')}
                >
                  <Lock size={15} aria-hidden="true" />
                  <span>Encrypt</span>
                </button>

                <button
                  type="button"
                  role="tab"
                  aria-selected={activeTab === 'decrypt'}
                  className="tab-btn"
                  style={{
                    borderRadius: 'var(--sb-radius-pill)',
                    padding: '8px 16px',
                    border: activeTab === 'decrypt' ? '1px solid var(--sb-border)' : '1px solid transparent',
                  }}
                  onClick={() => handleTabClick('decrypt')}
                >
                  <Unlock size={15} aria-hidden="true" />
                  <span>Decrypt</span>
                </button>

                <button
                  type="button"
                  role="tab"
                  aria-selected={activeTab === 'vault'}
                  className="tab-btn"
                  style={{
                    borderRadius: 'var(--sb-radius-pill)',
                    padding: '8px 16px',
                    border: activeTab === 'vault' ? '1px solid var(--sb-border)' : '1px solid transparent',
                  }}
                  onClick={() => handleTabClick('vault')}
                >
                  <HardDrive size={15} aria-hidden="true" />
                  <span>
                    Private Document Vault {!user && <span style={{ fontSize: '0.6875rem', opacity: 0.7 }}>(Account Required)</span>}
                  </span>
                </button>
              </nav>

              {user ? (
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={async () => {
                    await logout();
                    if (activeTab === 'vault') setActiveTab('encrypt');
                  }}
                  title="Log Out"
                >
                  <LogOut size={14} aria-hidden="true" />
                  <span>Log Out</span>
                </button>
              ) : (
                <button
                  type="button"
                  className="btn btn-primary btn-sm"
                  onClick={() => handleOpenAuth('register')}
                >
                  <UserPlus size={14} aria-hidden="true" />
                  <span>Register</span>
                </button>
              )}
            </div>
          </div>

          {/* Active Panel View */}
          <section id={`panel-${activeTab}`} role="tabpanel">
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

          <footer style={{ marginTop: 'auto', paddingTop: '24px', fontSize: '0.75rem', color: 'var(--sb-text-muted)' }}>
            <p>
              <strong>Security Guarantee:</strong> Client-side AES-256-GCM encryption &amp; SHA-256 integrity verification. Keys and plaintext never leave browser memory.
            </p>
          </footer>
        </main>
      </div>

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

