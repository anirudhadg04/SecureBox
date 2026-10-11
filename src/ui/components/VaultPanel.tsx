import React, { useEffect, useState } from 'react';
import {
  FileText,
  Download,
  Trash2,
  Share2,
  Search,
  HardDrive,
  RefreshCw,
  FolderArchive,
  ArrowUpDown,
  Lock,
  Users,
  Clock,
} from 'lucide-react';
import { api, VaultDocument, SharedDocumentItem } from '../../services/api';
import { formatFileSize } from '../components/common/FileDropzone';
import { Banner } from '../components/common/Banner';
import { ShareModal } from './ShareModal';
import { useAuth } from '../context/AuthContext';
import { unwrapKeyAsRecipient } from '../../core/crypto/sharingKeyUtils';
import { bytesToHex } from '../../core/crypto/keyUtils';

export const VaultPanel: React.FC = () => {
  const [documents, setDocuments] = useState<VaultDocument[]>([]);
  const [sharedWithMe, setSharedWithMe] = useState<SharedDocumentItem[]>([]);
  const [usageBytes, setUsageBytes] = useState<number>(0);
  const [quotaBytes, setQuotaBytes] = useState<number>(104857600);

  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [sortField, setSortField] = useState<'name' | 'created_at' | 'ciphertext_size'>('created_at');
  const [sortAsc, setSortAsc] = useState<boolean>(false);

  const [activeTab, setActiveTab] = useState<'mine' | 'shared'>('mine');
  const [sharingDoc, setSharingDoc] = useState<VaultDocument | null>(null);

  // Unwrapped key helper state for shared items
  const [unwrappedKeys, setUnwrappedKeys] = useState<Record<string, string>>({});
  const [unwrappingShareId, setUnwrappingShareId] = useState<string | null>(null);

  const { user, sharingPrivateKey } = useAuth();

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [docsRes, sharedRes] = await Promise.all([
        api.listDocuments(),
        api.listSharedWithMe(),
      ]);
      setDocuments(docsRes.documents);
      setUsageBytes(docsRes.usageBytes);
      setQuotaBytes(docsRes.quotaBytes);
      setSharedWithMe(sharedRes.shares);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load vault items.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleDelete = async (doc: VaultDocument) => {
    if (!window.confirm(`Permanently delete "${doc.name}" from your vault?`)) return;
    try {
      await api.deleteDocument(doc.id);
      setDocuments((prev) => prev.filter((d) => d.id !== doc.id));
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Delete failed');
    }
  };

  const handleDownload = async (docId: string, filename: string) => {
    try {
      const blob = await api.downloadDocumentBlob(docId);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${filename}.sbox`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Download failed');
    }
  };

  const handleUnwrapSharedKey = async (share: SharedDocumentItem) => {
    if (!sharingPrivateKey || !user) {
      alert('Sharing private key not loaded for this session.');
      return;
    }
    setUnwrappingShareId(share.share_id);
    try {
      const contextInfo = `doc:${share.document_id}:recipient:${user.id}:v1`;
      const unwrappedBytes = await unwrapKeyAsRecipient(
        share.wrapped_key_recipient,
        share.ephemeralPublicKeyJwk,
        sharingPrivateKey,
        contextInfo
      );
      const hex = bytesToHex(unwrappedBytes);
      setUnwrappedKeys((prev) => ({ ...prev, [share.share_id]: hex }));
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to unwrap shared key.');
    } finally {
      setUnwrappingShareId(null);
    }
  };

  const filteredDocs = documents
    .filter((d) => d.name.toLowerCase().includes(searchQuery.toLowerCase()))
    .sort((a, b) => {
      let valA = a[sortField];
      let valB = b[sortField];
      if (typeof valA === 'string') {
        valA = (valA as string).toLowerCase();
        valB = (valB as string).toLowerCase();
      }
      if (valA < valB) return sortAsc ? -1 : 1;
      if (valA > valB) return sortAsc ? 1 : -1;
      return 0;
    });

  const percentUsed = Math.min(100, Math.round((usageBytes / quotaBytes) * 100));

  return (
    <div className="panel-card vault-container">
      <div className="panel-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <h2 className="panel-title">Private Document Vault</h2>
          <p className="panel-subtitle">
            Zero-knowledge encrypted storage. Plaintext and keys never leave your browser unencrypted.
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div className="storage-meter">
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              <HardDrive size={14} aria-hidden="true" />
              <span>
                {formatFileSize(usageBytes)} / {formatFileSize(quotaBytes)} ({percentUsed}%)
              </span>
            </div>
            <div className="meter-track">
              <div className="meter-fill" style={{ width: `${percentUsed}%` }} />
            </div>
          </div>
          <button type="button" className="btn btn-secondary btn-sm" onClick={loadData} disabled={loading} title="Refresh vault">
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} aria-hidden="true" />
          </button>
        </div>
      </div>

      {error && <Banner variant="error" title="Vault Notice">{error}</Banner>}

      {/* Summary Section Metrics */}
      <div className="vault-metrics-grid">
        <div className="metric-card">
          <div className="metric-icon-wrap">
            <FileText size={20} aria-hidden="true" />
          </div>
          <div>
            <div className="metric-label">Total Documents</div>
            <div className="metric-value">{documents.length}</div>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-icon-wrap">
            <HardDrive size={20} aria-hidden="true" />
          </div>
          <div>
            <div className="metric-label">Storage Used</div>
            <div className="metric-value">{formatFileSize(usageBytes)}</div>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-icon-wrap">
            <Users size={20} aria-hidden="true" />
          </div>
          <div>
            <div className="metric-label">Shared With Me</div>
            <div className="metric-value">{sharedWithMe.length}</div>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-icon-wrap">
            <Clock size={20} aria-hidden="true" />
          </div>
          <div>
            <div className="metric-label">Recent Updates</div>
            <div className="metric-value" style={{ fontSize: '0.95rem', fontWeight: 600 }}>
              {documents.length > 0 ? new Date(documents[0].created_at).toLocaleDateString() : 'None'}
            </div>
          </div>
        </div>
      </div>

      {/* Tabs between My Vault and Shared With Me */}
      <div className="vault-tabs" style={{ display: 'flex', gap: '8px', borderBottom: '1px solid var(--sb-border)', marginBottom: '16px' }}>
        <button
          type="button"
          className={`tab-btn ${activeTab === 'mine' ? 'active' : ''}`}
          onClick={() => setActiveTab('mine')}
          style={{ borderBottom: activeTab === 'mine' ? '2px solid var(--text-primary)' : '2px solid transparent' }}
        >
          <span>My Documents ({documents.length})</span>
        </button>
        <button
          type="button"
          className={`tab-btn ${activeTab === 'shared' ? 'active' : ''}`}
          onClick={() => setActiveTab('shared')}
          style={{ borderBottom: activeTab === 'shared' ? '2px solid var(--text-primary)' : '2px solid transparent' }}
        >
          <span>Shared With Me ({sharedWithMe.length})</span>
        </button>
      </div>

      {activeTab === 'mine' && (
        <div>
          {/* Search and Sort Toolbar */}
          <div style={{ display: 'flex', justifyContent: 'space-between', gap: '12px', marginBottom: '16px', flexWrap: 'wrap' }}>
            <div style={{ position: 'relative', flex: '1', minWidth: '220px' }}>
              <Search size={16} style={{ position: 'absolute', left: '10px', top: '10px', color: 'var(--text-muted)' }} />
              <input
                type="text"
                className="form-input"
                style={{ paddingLeft: '32px' }}
                placeholder="Search documents..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
              <span style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>Sort by:</span>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => {
                  if (sortField === 'created_at') setSortField('name');
                  else if (sortField === 'name') setSortField('ciphertext_size');
                  else setSortField('created_at');
                  setSortAsc(!sortAsc);
                }}
              >
                <ArrowUpDown size={14} aria-hidden="true" />
                <span>{sortField === 'name' ? 'Name' : sortField === 'ciphertext_size' ? 'Size' : 'Date'}</span>
              </button>
            </div>
          </div>

          {/* Documents Table / List */}
          {filteredDocs.length === 0 ? (
            <div className="empty-vault-state" style={{ textAlign: 'center', padding: '40px 16px', color: 'var(--text-muted)' }}>
              <Lock size={36} style={{ margin: '0 auto 12px', opacity: 0.5 }} />
              <p>No documents found in your private vault.</p>
              <p style={{ fontSize: '0.8125rem', marginTop: '4px' }}>
                Use the Encrypt workspace above to encrypt and store documents in SecureBox.
              </p>
            </div>
          ) : (
            <div className="vault-table-wrapper" style={{ overflowX: 'auto' }}>
              <table className="vault-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.875rem' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border-subtle)', textAlign: 'left', color: 'var(--text-secondary)' }}>
                    <th style={{ padding: '10px 12px' }}>Name</th>
                    <th style={{ padding: '10px 12px' }}>Format</th>
                    <th style={{ padding: '10px 12px' }}>Encrypted Size</th>
                    <th style={{ padding: '10px 12px' }}>Upload Date</th>
                    <th style={{ padding: '10px 12px' }}>Shares</th>
                    <th style={{ padding: '10px 12px', textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredDocs.map((doc) => (
                    <tr key={doc.id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                      <td style={{ padding: '12px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          {doc.format_version === 2 ? (
                            <FolderArchive size={18} color="var(--border-focus)" />
                          ) : (
                            <FileText size={18} color="var(--text-secondary)" />
                          )}
                          <span style={{ fontWeight: 500 }} title={doc.name}>
                            {doc.name}
                          </span>
                        </div>
                      </td>
                      <td style={{ padding: '12px', color: 'var(--text-secondary)' }}>
                        {doc.format_version === 2 ? `Archive (${doc.file_count} files)` : 'Single File'}
                      </td>
                      <td style={{ padding: '12px' }}>{formatFileSize(doc.ciphertext_size)}</td>
                      <td style={{ padding: '12px', color: 'var(--text-secondary)' }}>
                        {new Date(doc.created_at).toLocaleDateString()}
                      </td>
                      <td style={{ padding: '12px' }}>
                        {doc.active_shares_count && doc.active_shares_count > 0 ? (
                          <span className="badge-shared">{doc.active_shares_count} shared</span>
                        ) : (
                          <span style={{ color: 'var(--text-muted)' }}>Private</span>
                        )}
                      </td>
                      <td style={{ padding: '12px', textAlign: 'right' }}>
                        <div style={{ display: 'inline-flex', gap: '6px' }}>
                          <button
                            type="button"
                            className="btn btn-secondary btn-sm"
                            onClick={() => handleDownload(doc.id, doc.name)}
                            title="Download .sbox file"
                          >
                            <Download size={14} aria-hidden="true" />
                          </button>
                          <button
                            type="button"
                            className="btn btn-secondary btn-sm"
                            onClick={() => setSharingDoc(doc)}
                            title="Share with user"
                          >
                            <Share2 size={14} aria-hidden="true" />
                          </button>
                          <button
                            type="button"
                            className="btn btn-secondary btn-sm"
                            onClick={() => handleDelete(doc)}
                            title="Delete permanently"
                            style={{ color: 'var(--state-error-text)' }}
                          >
                            <Trash2 size={14} aria-hidden="true" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {activeTab === 'shared' && (
        <div>
          {sharedWithMe.length === 0 ? (
            <div className="empty-vault-state" style={{ textAlign: 'center', padding: '40px 16px', color: 'var(--text-muted)' }}>
              <Share2 size={36} style={{ margin: '0 auto 12px', opacity: 0.5 }} />
              <p>No documents have been shared with you yet.</p>
            </div>
          ) : (
            <div className="vault-table-wrapper" style={{ overflowX: 'auto' }}>
              <table className="vault-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.875rem' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border-subtle)', textAlign: 'left', color: 'var(--text-secondary)' }}>
                    <th style={{ padding: '10px 12px' }}>Document Name</th>
                    <th style={{ padding: '10px 12px' }}>Shared By</th>
                    <th style={{ padding: '10px 12px' }}>Size</th>
                    <th style={{ padding: '10px 12px' }}>Date</th>
                    <th style={{ padding: '10px 12px' }}>Key Material</th>
                    <th style={{ padding: '10px 12px', textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {sharedWithMe.map((item) => {
                    const keyHex = unwrappedKeys[item.share_id];
                    return (
                      <tr key={item.share_id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                        <td style={{ padding: '12px', fontWeight: 500 }}>{item.document_name}</td>
                        <td style={{ padding: '12px', color: 'var(--border-focus)' }}>@{item.sender_username}</td>
                        <td style={{ padding: '12px' }}>{formatFileSize(item.ciphertext_size)}</td>
                        <td style={{ padding: '12px', color: 'var(--text-secondary)' }}>
                          {new Date(item.shared_at).toLocaleDateString()}
                        </td>
                        <td style={{ padding: '12px' }}>
                          {keyHex ? (
                            <code style={{ fontSize: '0.75rem', background: 'var(--bg-subtle)', padding: '2px 6px', borderRadius: '4px' }}>
                              {keyHex.slice(0, 8)}...{keyHex.slice(-8)}
                            </code>
                          ) : (
                            <button
                              type="button"
                              className="btn btn-secondary btn-sm"
                              onClick={() => handleUnwrapSharedKey(item)}
                              disabled={unwrappingShareId === item.share_id}
                            >
                              <Lock size={12} aria-hidden="true" />
                              <span>{unwrappingShareId === item.share_id ? 'Unwrapping...' : 'Unwrap Key'}</span>
                            </button>
                          )}
                        </td>
                        <td style={{ padding: '12px', textAlign: 'right' }}>
                          <button
                            type="button"
                            className="btn btn-primary btn-sm"
                            onClick={() => handleDownload(item.document_id, item.document_name)}
                          >
                            <Download size={14} aria-hidden="true" />
                            <span>Download .sbox</span>
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {sharingDoc && (
        <ShareModal
          document={sharingDoc}
          onClose={() => setSharingDoc(null)}
          onShareCreated={() => {
            loadData();
          }}
        />
      )}
    </div>
  );
};
