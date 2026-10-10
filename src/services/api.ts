export interface User {
  id: string;
  username: string;
  email: string;
  role: string;
  storageQuotaBytes: number;
}

export interface VaultDocument {
  id: string;
  name: string;
  ciphertext_size: number;
  plaintext_size: number;
  mime_type: string;
  format_version: number;
  file_count: number;
  sha256_ciphertext: string;
  wrapped_key_owner: string;
  created_at: number;
  updated_at: number;
  active_shares_count?: number;
}

export interface SharedDocumentItem {
  share_id: string;
  document_id: string;
  wrapped_key_recipient: string;
  ephemeralPublicKeyJwk: JsonWebKey;
  shared_at: number;
  sender_username: string;
  document_name: string;
  ciphertext_size: number;
  plaintext_size: number;
  mime_type: string;
  format_version: number;
  file_count: number;
}

class ApiService {
  private csrfToken: string | null = null;

  setCsrfToken(token: string | null): void {
    this.csrfToken = token;
  }

  getCsrfToken(): string | null {
    return this.csrfToken;
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const headers = new Headers(options.headers || {});
    if (this.csrfToken && !['GET', 'HEAD', 'OPTIONS'].includes(options.method || 'GET')) {
      headers.set('X-SecureBox-CSRF', this.csrfToken);
    }
    if (!(options.body instanceof FormData) && !headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
    }

    const response = await fetch(endpoint, {
      ...options,
      headers,
    });

    if (!response.ok) {
      let errorMessage = `Request failed (${response.status})`;
      try {
        const errorData = await response.json();
        if (errorData.error) errorMessage = errorData.error;
      } catch {
        // Fall back to default
      }
      throw new Error(errorMessage);
    }

    // For file download blobs
    if (response.headers.get('content-type')?.includes('application/octet-stream')) {
      return (await response.blob()) as unknown as T;
    }

    return response.json() as Promise<T>;
  }

  // Auth endpoints
  async register(username: string, email: string, password: string): Promise<{ user: User; csrfToken: string }> {
    const data = await this.request<{ user: User; csrfToken: string }>('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ username, email, password }),
    });
    this.csrfToken = data.csrfToken;
    return data;
  }

  async login(identifier: string, password: string): Promise<{ user: User; csrfToken: string }> {
    const data = await this.request<{ user: User; csrfToken: string }>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ identifier, password }),
    });
    this.csrfToken = data.csrfToken;
    return data;
  }

  async logout(): Promise<void> {
    await this.request('/api/auth/logout', { method: 'POST' });
    this.csrfToken = null;
  }

  async getMe(): Promise<{ user: User | null; csrfToken?: string }> {
    try {
      const data = await this.request<{ user: User | null; csrfToken?: string }>('/api/auth/me');
      if (data.csrfToken) this.csrfToken = data.csrfToken;
      return data;
    } catch {
      return { user: null };
    }
  }

  async forgotPassword(email: string): Promise<{ message: string; devResetToken?: string }> {
    return this.request<{ message: string; devResetToken?: string }>('/api/auth/forgot-password', {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
  }

  async resetPassword(token: string, newPassword: string): Promise<{ message: string }> {
    return this.request<{ message: string }>('/api/auth/reset-password', {
      method: 'POST',
      body: JSON.stringify({ token, newPassword }),
    });
  }

  // Document Vault endpoints
  async listDocuments(): Promise<{ documents: VaultDocument[]; usageBytes: number; quotaBytes: number }> {
    return this.request('/api/documents');
  }

  async uploadDocument(payload: {
    name: string;
    ciphertextBase64: string;
    plaintextSize: number;
    mimeType: string;
    formatVersion: number;
    fileCount: number;
    sha256Ciphertext: string;
    wrappedKeyOwner: string;
  }): Promise<{ id: string; name: string }> {
    return this.request('/api/documents', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async downloadDocumentBlob(docId: string): Promise<Blob> {
    return this.request<Blob>(`/api/documents/${docId}/download`);
  }

  async deleteDocument(docId: string): Promise<{ message: string }> {
    return this.request(`/api/documents/${docId}`, { method: 'DELETE' });
  }

  // Sharing endpoints
  async getRecipientPublicKey(username: string): Promise<{ userId: string; username: string; publicKeyJwk: JsonWebKey }> {
    return this.request(`/api/sharing/public-key/${encodeURIComponent(username)}`);
  }

  async saveSharingKeypair(payload: { publicKeyJwk: JsonWebKey; encryptedPrivateKey: string }): Promise<void> {
    await this.request('/api/sharing/keypair', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async getMyKeypair(): Promise<{ publicKeyJwk: JsonWebKey; encryptedPrivateKey: string } | null> {
    try {
      return await this.request('/api/sharing/keypair');
    } catch {
      return null;
    }
  }

  async shareDocument(payload: {
    documentId: string;
    recipientUsername: string;
    wrappedKeyRecipient: string;
    ephemeralPublicKeyJwk: JsonWebKey;
  }): Promise<{ shareId: string }> {
    return this.request('/api/sharing/share', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async listSharedWithMe(): Promise<{ shares: SharedDocumentItem[] }> {
    return this.request('/api/sharing/shared-with-me');
  }

  async revokeShare(shareId: string): Promise<{ message: string }> {
    return this.request('/api/sharing/revoke', {
      method: 'POST',
      body: JSON.stringify({ shareId }),
    });
  }
}

export const api = new ApiService();
