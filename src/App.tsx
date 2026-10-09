import React, { useState } from 'react';
import { Lock, Unlock, ShieldCheck, Shield } from 'lucide-react';
import { EncryptPanel } from './ui/components/EncryptPanel';
import { DecryptPanel } from './ui/components/DecryptPanel';
import { VerifyPanel } from './ui/components/VerifyPanel';

type ActiveTab = 'encrypt' | 'decrypt' | 'verify';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<ActiveTab>('encrypt');

  return (
    <div className="app-container">
      <header className="app-header" role="banner">
        <div className="brand-row">
          <Shield size={28} aria-hidden="true" />
          <h1 className="brand-title">SecureBox</h1>
          <span className="brand-badge">Client-Side Only</span>
        </div>
        <p className="app-description">
          Local document encryption and cryptographic fingerprinting. Plaintext and keys never leave your device.
        </p>
      </header>

      <main role="main">
        <nav className="tabs-nav" role="tablist" aria-label="Document protection operations">
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'encrypt'}
            aria-controls="panel-encrypt"
            id="tab-encrypt"
            className="tab-btn"
            onClick={() => setActiveTab('encrypt')}
          >
            <Lock size={16} aria-hidden="true" />
            <span>Encrypt Document</span>
          </button>

          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'decrypt'}
            aria-controls="panel-decrypt"
            id="tab-decrypt"
            className="tab-btn"
            onClick={() => setActiveTab('decrypt')}
          >
            <Unlock size={16} aria-hidden="true" />
            <span>Decrypt Document</span>
          </button>

          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'verify'}
            aria-controls="panel-verify"
            id="tab-verify"
            className="tab-btn"
            onClick={() => setActiveTab('verify')}
          >
            <ShieldCheck size={16} aria-hidden="true" />
            <span>Verify Fingerprint (SHA-256)</span>
          </button>
        </nav>

        <section
          id={`panel-${activeTab}`}
          role="tabpanel"
          aria-labelledby={`tab-${activeTab}`}
        >
          {activeTab === 'encrypt' && <EncryptPanel />}
          {activeTab === 'decrypt' && <DecryptPanel />}
          {activeTab === 'verify' && <VerifyPanel />}
        </section>
      </main>

      <footer className="app-footer" role="contentinfo">
        <p>
          <strong>Security Guarantee:</strong> All operations run locally inside your browser via the native Web
          Crypto API (AES-256-GCM and SHA-256). No backend server, cloud storage, external analytics, or key escrow
          is utilized.
        </p>
        <p style={{ marginTop: '6px' }}>
          <strong>Notice:</strong> Document encryption requires safe retention of your 256-bit key. SecureBox cannot
          recover files if the key is lost. SHA-256 fingerprints verify data integrity against a reference, not the
          identity of the author.
        </p>
      </footer>
    </div>
  );
};

export default App;
