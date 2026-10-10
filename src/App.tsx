import React, { useState } from 'react';
import { Lock, Unlock, Shield } from 'lucide-react';
import { EncryptPanel } from './ui/components/EncryptPanel';
import { DecryptPanel } from './ui/components/DecryptPanel';

type WorkspaceMode = 'encrypt' | 'decrypt' | 'split';

export const App: React.FC = () => {
  const [workspaceMode, setWorkspaceMode] = useState<WorkspaceMode>('split');

  return (
    <div className="app-container">
      <header className="app-header" role="banner">
        <div className="brand-row">
          <Shield size={28} aria-hidden="true" />
          <h1 className="brand-title">SecureBox</h1>
          <span className="brand-badge">Client-Side E2EE</span>
        </div>
        <p className="app-description">
          Security-first document protection with authenticated AES-256-GCM encryption and tamper-proof <code>.sbox</code> containers. Plaintext and keys never leave your device unencrypted.
        </p>
      </header>

      <main role="main">
        {/* Workspace mode switcher for mobile or focused mode */}
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
      </main>

      <footer className="app-footer" role="contentinfo">
        <p>
          <strong>Security Guarantee:</strong> All document encryption and decryption runs 100% locally in your browser memory using the native Web Crypto API (AES-256-GCM authenticated cipher with SHA-256 file manifest verification). Plaintext documents and raw encryption keys are never sent over the network.
        </p>
        <p style={{ marginTop: '6px' }}>
          <strong>Notice:</strong> Document encryption requires safe retention of your 256-bit key. SecureBox cannot recover encrypted files if the key is lost.
        </p>
      </footer>
    </div>
  );
};

export default App;
