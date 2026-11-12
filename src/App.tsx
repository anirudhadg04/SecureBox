import React, { useState, useEffect, useRef } from 'react';
import {
  Lock,
  Unlock,
  HardDrive,
  LogOut,
  UserPlus,
  Search,
  ChevronDown,
  LayoutGrid,
  Share2,
  Users,
  X,
  Layers,
} from 'lucide-react';
import { EncryptPanel } from './ui/components/EncryptPanel';
import { DecryptPanel } from './ui/components/DecryptPanel';
import { VaultPanel } from './ui/components/VaultPanel';
import { AuthModal } from './ui/components/AuthModal';
import { AuthProvider, useAuth } from './ui/context/AuthContext';
import { api, SharedDocumentItem, SharedByMeDocumentItem } from './services/api';
import { Banner } from './ui/components/common/Banner';

export type NavigationSection =
  | 'encrypt'
  | 'decrypt'
  | 'vault'
  | 'shared-with-me'
  | 'shared-by-me'
  | 'libraries-coming-soon';

const AppContent: React.FC = () => {
  const [activeSection, setActiveSection] = useState<NavigationSection>('encrypt');
  const [showAuthModal, setShowAuthModal] = useState<boolean>(false);
  const [authModalMode, setAuthModalMode] = useState<'login' | 'register'>('register');
  const [workspaceOpen, setWorkspaceOpen] = useState<boolean>(true);
  const [documentsOpen, setDocumentsOpen] = useState<boolean>(true);
  const [collabOpen, setCollabOpen] = useState<boolean>(true);

  // Contextual search state
  const [searchQuery, setSearchQuery] = useState<string>('');
  const searchInputRef = useRef<HTMLInputElement>(null);

  // Collaborator filtering state
  const [selectedCollaborator, setSelectedCollaborator] = useState<string | null>(null);

  // Real sharing lists for badges and collaborator rail
  const [sharedWithMeList, setSharedWithMeList] = useState<SharedDocumentItem[]>([]);
  const [sharedByMeList, setSharedByMeList] = useState<SharedByMeDocumentItem[]>([]);

  const {
    user,
    isLoading,
    isLoggingOut,
    logout,
    logoutNotice,
    clearLogoutNotice,
    sessionEpoch,
  } = useAuth();

  const userRef = useRef<typeof user>(user);
  userRef.current = user;

  // Reset transient filters and navigate away from protected views when session teardown occurs
  useEffect(() => {
    if (!user) {
      if (
        activeSection === 'vault' ||
        activeSection === 'shared-with-me' ||
        activeSection === 'shared-by-me'
      ) {
        setActiveSection('encrypt');
      }
    }
    setSearchQuery('');
    setSelectedCollaborator(null);
  }, [user, sessionEpoch]);

  // Load real sharing records when authenticated, update reactively on shares-updated event
  const loadSharingData = React.useCallback(() => {
    if (!user) {
      setSharedWithMeList([]);
      setSharedByMeList([]);
      setSelectedCollaborator(null);
      return;
    }
    Promise.all([
      api.listSharedWithMe().catch(() => ({ shares: [] })),
      api.listSharedByMe().catch(() => ({ shares: [] })),
    ]).then(([inbound, outbound]) => {
      if (!userRef.current) return;
      setSharedWithMeList(inbound.shares || []);
      setSharedByMeList(outbound.shares || []);
    }).catch(() => {});
  }, [user]);

  useEffect(() => {
    loadSharingData();
    window.addEventListener('securebox:shares-updated', loadSharingData);
    return () => {
      window.removeEventListener('securebox:shares-updated', loadSharingData);
    };
  }, [loadSharingData, sessionEpoch]);

  // Browser History and bfcache protection: re-validate authentication on navigation
  useEffect(() => {
    const handleHistoryNav = async (e: Event) => {
      const pageshowEvt = e as PageTransitionEvent;
      if (pageshowEvt.persisted || e.type === 'popstate') {
        try {
          const { user: serverUser } = await api.getMe();
          if (!serverUser && userRef.current) {
            await logout();
          }
        } catch {
          if (userRef.current) await logout();
        }
      }
    };

    window.addEventListener('popstate', handleHistoryNav);
    window.addEventListener('pageshow', handleHistoryNav);

    return () => {
      window.removeEventListener('popstate', handleHistoryNav);
      window.removeEventListener('pageshow', handleHistoryNav);
    };
  }, [logout]);

  const handleLogout = async () => {
    setShowAuthModal(false);
    await logout();
    setActiveSection('encrypt');
    setSearchQuery('');
    setSelectedCollaborator(null);
  };

  // Derive real collaborators with deterministic avatars
  const realCollaborators = React.useMemo(() => {
    const map = new Map<string, { username: string; count: number; role: 'sender' | 'recipient' | 'both' }>();

    for (const item of sharedWithMeList) {
      const u = item.sender_username;
      const existing = map.get(u.toLowerCase());
      if (existing) {
        existing.count += 1;
        if (existing.role === 'recipient') existing.role = 'both';
      } else {
        map.set(u.toLowerCase(), { username: u, count: 1, role: 'sender' });
      }
    }

    for (const item of sharedByMeList) {
      const u = item.recipient_username;
      const existing = map.get(u.toLowerCase());
      if (existing) {
        existing.count += 1;
        if (existing.role === 'sender') existing.role = 'both';
      } else {
        map.set(u.toLowerCase(), { username: u, count: 1, role: 'recipient' });
      }
    }

    return Array.from(map.values());
  }, [sharedWithMeList, sharedByMeList]);

  // Keyboard shortcut listener (Ctrl+K / Cmd+K to focus search, Escape to clear)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        searchInputRef.current?.focus();
      } else if (e.key === 'Escape') {
        if (document.activeElement === searchInputRef.current) {
          if (searchQuery) {
            setSearchQuery('');
          } else {
            searchInputRef.current?.blur();
          }
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [searchQuery]);

  const handleOpenAuth = (mode: 'login' | 'register') => {
    setAuthModalMode(mode);
    setShowAuthModal(true);
  };

  const handleNavClick = (section: NavigationSection) => {
    if (section === 'vault' || section === 'shared-with-me' || section === 'shared-by-me') {
      if (!user) {
        handleOpenAuth('register');
        return;
      }
    }
    setActiveSection(section);
  };

  // Compute placeholder per section
  const searchPlaceholder = React.useMemo(() => {
    switch (activeSection) {
      case 'encrypt':
        return 'Filter selected files... (Ctrl+K)';
      case 'decrypt':
        return 'Filter selected files... (Ctrl+K)';
      case 'vault':
        return 'Search documents by name or format... (Ctrl+K)';
      case 'shared-with-me':
        return 'Search shared files by name or sender... (Ctrl+K)';
      case 'shared-by-me':
        return 'Search shared files by name or recipient... (Ctrl+K)';
      case 'libraries-coming-soon':
        return 'Search unavailable (Ctrl+K)';
      default:
        return 'Search... (Ctrl+K)';
    }
  }, [activeSection]);

  const handleCollaboratorClick = (username: string) => {
    if (selectedCollaborator?.toLowerCase() === username.toLowerCase()) {
      setSelectedCollaborator(null);
    } else {
      setSelectedCollaborator(username);
      if (activeSection !== 'shared-with-me' && activeSection !== 'shared-by-me' && activeSection !== 'vault') {
        setActiveSection('shared-with-me');
      }
    }
  };

  // Helper for deterministic avatar color from string
  const getAvatarBg = (name: string) => {
    const colors = ['#0284c7', '#2563eb', '#7c3aed', '#db2777', '#059669', '#d97706'];
    let hash = 0;
    for (let i = 0; i < name.length; i++) {
      hash = name.charCodeAt(i) + ((hash << 5) - hash);
    }
    return colors[Math.abs(hash) % colors.length];
  };

  // Render neutral loading/teardown screens to enforce rendering boundaries
  if (isLoading) {
    return (
      <div className="app-viewport">
        <div className="lava-lamp-bg" aria-hidden="true">
          <div className="blob blob-1" />
          <div className="blob blob-2" />
        </div>
        <div
          className="glass-window"
          style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '380px' }}
        >
          <div style={{ textAlign: 'center', padding: '40px' }}>
            <div style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--sb-text)', marginBottom: '6px' }}>
              Initializing SecureBox...
            </div>
            <p style={{ fontSize: '0.85rem', color: 'var(--sb-text-muted)' }}>
              Validating secure cryptographic sandbox
            </p>
          </div>
        </div>
      </div>
    );
  }

  if (isLoggingOut) {
    return (
      <div className="app-viewport">
        <div className="lava-lamp-bg" aria-hidden="true">
          <div className="blob blob-1" />
          <div className="blob blob-2" />
        </div>
        <div
          className="glass-window"
          style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '380px' }}
        >
          <div style={{ textAlign: 'center', padding: '40px' }}>
            <div style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--sb-text)', marginBottom: '6px' }}>
              Signing out securely...
            </div>
            <p style={{ fontSize: '0.85rem', color: 'var(--sb-text-muted)' }}>
              Purging transient cryptographic keys and memory
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="app-viewport">
      {/* Lava-Lamp Ambient Background Blobs */}
      <div className="lava-lamp-bg" aria-hidden="true">
        <div className="blob blob-1" />
        <div className="blob blob-2" />
        <div className="blob blob-3" />
        <div className="blob blob-4" />
      </div>

      {/* Main Glass Window Shell */}
      <div className="glass-window">
        {/* Leftmost slim icon rail */}
        <aside className="icon-rail" aria-label="Quick Switcher">
          <div
            className="rail-avatar"
            title={user ? `${user.username} (${user.email})` : 'Guest User'}
          >
            {user ? (
              user.username.slice(0, 2).toUpperCase()
            ) : (
              <span style={{ fontSize: '0.85rem' }}>SB</span>
            )}
          </div>

          <div className="sidebar-section-title" style={{ fontSize: '0.625rem', marginTop: '8px' }}>
            MAIN
          </div>

          <button
            type="button"
            className={`rail-btn ${activeSection === 'encrypt' ? 'active' : ''}`}
            onClick={() => handleNavClick('encrypt')}
            title="Encrypt Documents"
          >
            <LayoutGrid size={20} />
          </button>

          <button
            type="button"
            className={`rail-btn ${activeSection === 'decrypt' ? 'active' : ''}`}
            onClick={() => handleNavClick('decrypt')}
            title="Decrypt Documents"
          >
            <Unlock size={20} />
          </button>

          <button
            type="button"
            className={`rail-btn ${activeSection === 'vault' ? 'active' : ''}`}
            onClick={() => handleNavClick('vault')}
            title="Private Document Vault"
          >
            <HardDrive size={20} />
          </button>

          {/* Real Collaborators Section in Rail: only shown when actual sharing relationships exist */}
          {user && realCollaborators.length > 0 && (
            <>
              <div className="rail-divider" />
              <div className="sidebar-section-title" style={{ fontSize: '0.625rem' }}>
                COLLAB
              </div>

              {realCollaborators.slice(0, 5).map((collab) => {
                const isSelected = selectedCollaborator?.toLowerCase() === collab.username.toLowerCase();
                return (
                  <div
                    key={collab.username}
                    className="rail-collaborator-dot"
                    style={{
                      background: getAvatarBg(collab.username),
                      outline: isSelected ? '2px solid var(--sb-primary)' : 'none',
                      outlineOffset: '2px',
                    }}
                    onClick={() => handleCollaboratorClick(collab.username)}
                    title={`Collaborator: @${collab.username} (${collab.count} document${collab.count > 1 ? 's' : ''}) • Click to filter`}
                    role="button"
                    tabIndex={0}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        handleCollaboratorClick(collab.username);
                      }
                    }}
                  >
                    {collab.username.slice(0, 2).toUpperCase()}
                  </div>
                );
              })}
            </>
          )}
        </aside>

        {/* Sidebar Navigation - Single Source of Navigation Truth */}
        <aside className="glass-sidebar" aria-label="Main Navigation">
          <div className="sidebar-logo">
            <div className="logo-graphic">
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

          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            {/* 1. Workspace Section */}
            <div>
              <button
                type="button"
                className="sidebar-nav-item"
                onClick={() => setWorkspaceOpen(!workspaceOpen)}
                style={{ padding: '6px 10px', marginBottom: '2px' }}
              >
                <span className="sidebar-section-title" style={{ margin: 0 }}>WORKSPACE</span>
                <ChevronDown
                  size={14}
                  style={{
                    transform: workspaceOpen ? 'rotate(180deg)' : 'rotate(0deg)',
                    transition: 'transform 0.2s ease',
                    color: 'var(--sb-text-muted)',
                  }}
                />
              </button>

              {workspaceOpen && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
                  <button
                    type="button"
                    className={`sidebar-nav-item ${activeSection === 'encrypt' ? 'active' : ''}`}
                    onClick={() => handleNavClick('encrypt')}
                  >
                    <span style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <Lock size={16} />
                      <span>Encrypt</span>
                    </span>
                  </button>

                  <button
                    type="button"
                    className={`sidebar-nav-item ${activeSection === 'decrypt' ? 'active' : ''}`}
                    onClick={() => handleNavClick('decrypt')}
                  >
                    <span style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <Unlock size={16} />
                      <span>Decrypt</span>
                    </span>
                  </button>
                </div>
              )}
            </div>

            {/* 2. Documents Section */}
            <div>
              <button
                type="button"
                className="sidebar-nav-item"
                onClick={() => setDocumentsOpen(!documentsOpen)}
                style={{ padding: '6px 10px', marginBottom: '2px' }}
              >
                <span className="sidebar-section-title" style={{ margin: 0 }}>DOCUMENTS</span>
                <ChevronDown
                  size={14}
                  style={{
                    transform: documentsOpen ? 'rotate(180deg)' : 'rotate(0deg)',
                    transition: 'transform 0.2s ease',
                    color: 'var(--sb-text-muted)',
                  }}
                />
              </button>

              {documentsOpen && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
                  <button
                    type="button"
                    className={`sidebar-nav-item ${activeSection === 'vault' ? 'active' : ''}`}
                    onClick={() => handleNavClick('vault')}
                  >
                    <span style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <HardDrive size={16} />
                      <span>Document Vault</span>
                    </span>
                    {!user && (
                      <span style={{ fontSize: '0.6875rem', color: 'var(--sb-text-muted)' }}>Locked</span>
                    )}
                  </button>

                  <button
                    type="button"
                    className={`sidebar-nav-item ${activeSection === 'libraries-coming-soon' ? 'active' : ''}`}
                    onClick={() => handleNavClick('libraries-coming-soon')}
                  >
                    <span style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <Layers size={16} />
                      <span>Libraries</span>
                    </span>
                    <span
                      style={{
                        fontSize: '0.625rem',
                        background: 'rgba(148, 163, 184, 0.2)',
                        padding: '1px 6px',
                        borderRadius: '4px',
                        color: 'var(--sb-text-muted)',
                      }}
                    >
                      Soon
                    </span>
                  </button>
                </div>
              )}
            </div>

            {/* 3. Collaboration Section (Active when authenticated) */}
            {user && (
              <div>
                <button
                  type="button"
                  className="sidebar-nav-item"
                  onClick={() => setCollabOpen(!collabOpen)}
                  style={{ padding: '6px 10px', marginBottom: '2px' }}
                >
                  <span className="sidebar-section-title" style={{ margin: 0 }}>COLLABORATION</span>
                  <ChevronDown
                    size={14}
                    style={{
                      transform: collabOpen ? 'rotate(180deg)' : 'rotate(0deg)',
                      transition: 'transform 0.2s ease',
                      color: 'var(--sb-text-muted)',
                    }}
                  />
                </button>

                {collabOpen && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
                    <button
                      type="button"
                      className={`sidebar-nav-item ${activeSection === 'shared-with-me' ? 'active' : ''}`}
                      onClick={() => handleNavClick('shared-with-me')}
                    >
                      <span style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <Share2 size={16} />
                        <span>Shared with me</span>
                      </span>
                      {sharedWithMeList.length > 0 && (
                        <span className="sidebar-badge">{sharedWithMeList.length}</span>
                      )}
                    </button>

                    <button
                      type="button"
                      className={`sidebar-nav-item ${activeSection === 'shared-by-me' ? 'active' : ''}`}
                      onClick={() => handleNavClick('shared-by-me')}
                    >
                      <span style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <Users size={16} />
                        <span>Shared by me</span>
                      </span>
                      {sharedByMeList.length > 0 && (
                        <span
                          style={{
                            fontSize: '0.6875rem',
                            fontWeight: 700,
                            background: 'rgba(2, 132, 199, 0.15)',
                            color: 'var(--sb-primary)',
                            padding: '1px 6px',
                            borderRadius: '9999px',
                          }}
                        >
                          {sharedByMeList.length}
                        </span>
                      )}
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* User Session Footer Card */}
          <div style={{ marginTop: 'auto', paddingTop: '16px' }}>
            <div className="sidebar-section-title">USER SESSION</div>
            {user ? (
              <div
                style={{
                  background: 'rgba(255, 255, 255, 0.75)',
                  padding: '12px',
                  borderRadius: 'var(--sb-radius-sm)',
                  border: '1px solid var(--sb-border-subtle)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                  <div
                    style={{
                      width: '28px',
                      height: '28px',
                      borderRadius: '50%',
                      background: 'var(--sb-primary)',
                      color: '#fff',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontSize: '0.75rem',
                      fontWeight: 700,
                      flexShrink: 0,
                    }}
                  >
                    {user.username.slice(0, 2).toUpperCase()}
                  </div>
                  <div style={{ overflow: 'hidden' }}>
                    <div
                      style={{
                        fontSize: '0.8125rem',
                        fontWeight: 700,
                        color: 'var(--sb-text)',
                        textOverflow: 'ellipsis',
                        overflow: 'hidden',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {user.username}
                    </div>
                    <div
                      style={{
                        fontSize: '0.6875rem',
                        color: 'var(--sb-text-muted)',
                        textOverflow: 'ellipsis',
                        overflow: 'hidden',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {user.email}
                    </div>
                  </div>
                </div>
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  style={{ width: '100%' }}
                  onClick={handleLogout}
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

        {/* Main Content Area */}
        <main className="glass-main" role="main">
          {/* Top Bar with Contextual Search and Quick Actions */}
          <div className="main-topbar">
            <div className="search-pill-box" style={{ flex: '1', maxWidth: '440px' }}>
              <Search size={16} aria-hidden="true" />
              <input
                ref={searchInputRef}
                type="text"
                placeholder={searchPlaceholder}
                className="search-pill-input"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                aria-label="Contextual search"
              />
              {searchQuery && (
                <button
                  type="button"
                  onClick={() => setSearchQuery('')}
                  style={{
                    background: 'none',
                    border: 'none',
                    padding: 0,
                    cursor: 'pointer',
                    color: 'var(--sb-text-muted)',
                    display: 'flex',
                    alignItems: 'center',
                  }}
                  title="Clear search"
                  aria-label="Clear search"
                >
                  <X size={15} />
                </button>
              )}
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              {user ? (
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={handleLogout}
                  title="Log Out"
                >
                  <LogOut size={14} aria-hidden="true" />
                  <span>Log Out</span>
                </button>
              ) : (
                <div style={{ display: 'flex', gap: '8px' }}>
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
          </div>

          {/* Active View Display */}
          <section id={`panel-${activeSection}`} role="region">
            {logoutNotice && (
              <div style={{ marginBottom: '16px' }}>
                <Banner variant="warning" title="Session Notice">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%' }}>
                    <span>{logoutNotice}</span>
                    <button
                      type="button"
                      onClick={clearLogoutNotice}
                      style={{
                        background: 'none',
                        border: 'none',
                        cursor: 'pointer',
                        color: 'inherit',
                        fontWeight: 600,
                        padding: '2px 8px',
                      }}
                    >
                      Dismiss
                    </button>
                  </div>
                </Banner>
              </div>
            )}

            {activeSection === 'encrypt' && (
              <EncryptPanel
                key={`encrypt-${sessionEpoch}-${user?.id || 'guest'}`}
                onRequireRegister={() => handleOpenAuth('register')}
                searchFilter={searchQuery}
              />
            )}

            {activeSection === 'decrypt' && (
              <DecryptPanel
                key={`decrypt-${sessionEpoch}-${user?.id || 'guest'}`}
                searchFilter={searchQuery}
              />
            )}

            {activeSection === 'vault' && user && (
              <VaultPanel
                key={`vault-${sessionEpoch}-${user.id}`}
                externalSearchQuery={searchQuery}
                collaboratorFilter={selectedCollaborator}
                onClearCollaboratorFilter={() => setSelectedCollaborator(null)}
                vaultTab="mine"
                onVaultTabChange={(tab) => {
                  if (tab === 'shared-with-me') setActiveSection('shared-with-me');
                  else if (tab === 'shared-by-me') setActiveSection('shared-by-me');
                  else setActiveSection('vault');
                }}
              />
            )}

            {activeSection === 'shared-with-me' && user && (
              <VaultPanel
                key={`shared-with-${sessionEpoch}-${user.id}`}
                externalSearchQuery={searchQuery}
                collaboratorFilter={selectedCollaborator}
                onClearCollaboratorFilter={() => setSelectedCollaborator(null)}
                vaultTab="shared-with-me"
                onVaultTabChange={(tab) => {
                  if (tab === 'mine') setActiveSection('vault');
                  else if (tab === 'shared-by-me') setActiveSection('shared-by-me');
                }}
              />
            )}

            {activeSection === 'shared-by-me' && user && (
              <VaultPanel
                key={`shared-by-${sessionEpoch}-${user.id}`}
                externalSearchQuery={searchQuery}
                collaboratorFilter={selectedCollaborator}
                onClearCollaboratorFilter={() => setSelectedCollaborator(null)}
                vaultTab="shared-by-me"
                onVaultTabChange={(tab) => {
                  if (tab === 'mine') setActiveSection('vault');
                  else if (tab === 'shared-with-me') setActiveSection('shared-with-me');
                }}
              />
            )}

            {activeSection === 'libraries-coming-soon' && (
              <div className="panel-card" style={{ textAlign: 'center', padding: '60px 24px' }}>
                <Layers size={48} color="var(--sb-primary)" style={{ margin: '0 auto 16px', opacity: 0.8 }} />
                <h2 className="panel-title" style={{ fontSize: '1.25rem' }}>
                  Document Collections &amp; Libraries
                </h2>
                <p className="panel-subtitle" style={{ maxWidth: '480px', margin: '8px auto 20px' }}>
                  Libraries provide client-side folder collections and tagged classification for private vault items.
                  This feature is currently in design and will be available in an upcoming update.
                </p>
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={() => setActiveSection('vault')}
                >
                  Return to Document Vault
                </button>
              </div>
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

