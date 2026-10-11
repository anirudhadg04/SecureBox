import React, { useState } from 'react';
import { Lock, ArrowRight, ShieldCheck, KeyRound, Eye, EyeOff } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { Banner } from './common/Banner';
import { api } from '../../services/api';

interface AuthModalProps {
  initialMode?: 'login' | 'register' | 'forgot';
  onClose?: () => void;
}

export const AuthModal: React.FC<AuthModalProps> = ({ initialMode = 'login', onClose }) => {
  const [mode, setMode] = useState<'login' | 'register' | 'forgot'>(initialMode);
  const [identifier, setIdentifier] = useState('');
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [resetToken, setResetToken] = useState('');
  const [newPassword, setNewPassword] = useState('');

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const { login, register } = useAuth();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await login(identifier, password);
      if (onClose) onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Invalid credentials.');
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (password !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }
    setLoading(true);
    try {
      await register(username, email, password);
      if (onClose) onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to register account.');
    } finally {
      setLoading(false);
    }
  };

  const handleForgot = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await api.forgotPassword(email);
      setSuccessMsg(res.message);
      if (res.devResetToken) {
        setResetToken(res.devResetToken);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Recovery request failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await api.resetPassword(resetToken, newPassword);
      setSuccessMsg(res.message);
      setMode('login');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to reset password.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className='auth-card panel-card' style={{ position: 'relative' }}>
      {onClose && (
        <button
          type='button'
          className='btn btn-secondary btn-sm'
          onClick={onClose}
          style={{ position: 'absolute', top: '16px', right: '16px', padding: '4px 8px' }}
          aria-label='Close'
        >
          ✕
        </button>
      )}
      <div className='panel-header' style={{ textAlign: 'center', marginTop: '8px' }}>
        <h2 className='panel-title' style={{ fontSize: '1.4rem' }}>
          {mode === 'login' && 'Sign in to SecureBox Vault'}
          {mode === 'register' && 'Create SecureBox Account'}
          {mode === 'forgot' && 'Account Recovery'}
        </h2>
        <p className='panel-subtitle'>
          {mode === 'login' && 'Zero-knowledge private storage and encrypted sharing.'}
          {mode === 'register' && 'Password hashed with PBKDF2-SHA512. No plaintext stored.'}
          {mode === 'forgot' && 'Request a secure single-use recovery token.'}
        </p>
      </div>

      {error && <Banner variant='error' title='Authentication Error'>{error}</Banner>}
      {successMsg && <Banner variant='success' title='Success'>{successMsg}</Banner>}

      {mode === 'login' && (
        <form onSubmit={handleLogin} style={{ marginTop: '16px' }}>
          <div className='form-group' style={{ marginBottom: '14px' }}>
            <label className='form-label' htmlFor='auth-identifier'>
              Username or Email
            </label>
            <input
              id='auth-identifier'
              type='text'
              required
              className='form-input'
              value={identifier}
              onChange={(e) => setIdentifier(e.target.value)}
              placeholder='e.g. alice or alice@domain.com'
              disabled={loading}
            />
          </div>

          <div className='form-group' style={{ marginBottom: '18px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <label className='form-label' htmlFor='auth-password'>
                Password
              </label>
              <button
                type='button'
                className='btn-link'
                style={{ fontSize: '0.8rem', background: 'none', border: 'none', color: 'var(--sb-primary)', cursor: 'pointer' }}
                onClick={() => { setMode('forgot'); setError(null); setSuccessMsg(null); }}
              >
                Forgot password?
              </button>
            </div>
            <div style={{ position: 'relative' }}>
              <input
                id='auth-password'
                type={showPassword ? 'text' : 'password'}
                required
                className='form-input'
                style={{ paddingRight: '40px' }}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder='••••••••••••'
                disabled={loading}
              />
              <button
                type='button'
                onClick={() => setShowPassword(!showPassword)}
                style={{
                  position: 'absolute',
                  right: '10px',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  background: 'none',
                  border: 'none',
                  cursor: 'pointer',
                  color: 'var(--sb-text-muted)',
                  display: 'flex',
                  alignItems: 'center',
                }}
                aria-label={showPassword ? 'Hide password' : 'Show password'}
              >
                {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
          </div>

          <button type='submit' className='btn btn-primary' style={{ width: '100%', justifyContent: 'center' }} disabled={loading}>
            <Lock size={16} aria-hidden='true' />
            <span>{loading ? 'Authenticating...' : 'Sign In'}</span>
          </button>

          <div style={{ marginTop: '16px', textAlign: 'center', fontSize: '0.875rem' }}>
            <span style={{ color: 'var(--sb-text-secondary)' }}>Don't have an account? </span>
            <button
              type='button'
              className='btn-link'
              style={{ background: 'none', border: 'none', color: 'var(--sb-primary)', fontWeight: 600, cursor: 'pointer' }}
              onClick={() => { setMode('register'); setError(null); setSuccessMsg(null); }}
            >
              Register here
            </button>
          </div>
        </form>
      )}

      {mode === 'register' && (
        <form onSubmit={handleRegister} style={{ marginTop: '16px' }}>
          <div className='form-group' style={{ marginBottom: '12px' }}>
            <label className='form-label' htmlFor='reg-username'>
              Username
            </label>
            <input
              id='reg-username'
              type='text'
              required
              minLength={3}
              maxLength={32}
              className='form-input'
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder='alice'
              disabled={loading}
            />
          </div>

          <div className='form-group' style={{ marginBottom: '12px' }}>
            <label className='form-label' htmlFor='reg-email'>
              Email Address
            </label>
            <input
              id='reg-email'
              type='email'
              required
              className='form-input'
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder='alice@domain.com'
              disabled={loading}
            />
          </div>

          <div className='form-group' style={{ marginBottom: '14px' }}>
            <label className='form-label' htmlFor='reg-password'>
              Password (min. 8 characters)
            </label>
            <div style={{ position: 'relative' }}>
              <input
                id='reg-password'
                type={showPassword ? 'text' : 'password'}
                required
                minLength={8}
                className='form-input'
                style={{ paddingRight: '40px' }}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder='••••••••••••'
                disabled={loading}
              />
              <button
                type='button'
                onClick={() => setShowPassword(!showPassword)}
                style={{
                  position: 'absolute',
                  right: '10px',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  background: 'none',
                  border: 'none',
                  cursor: 'pointer',
                  color: 'var(--sb-text-muted)',
                  display: 'flex',
                  alignItems: 'center',
                }}
                aria-label={showPassword ? 'Hide password' : 'Show password'}
              >
                {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
          </div>

          <div className='form-group' style={{ marginBottom: '18px' }}>
            <label className='form-label' htmlFor='reg-confirm-password'>
              Confirm Password
            </label>
            <input
              id='reg-confirm-password'
              type={showPassword ? 'text' : 'password'}
              required
              minLength={8}
              className='form-input'
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder='••••••••••••'
              disabled={loading}
            />
          </div>

          <button type='submit' className='btn btn-primary' style={{ width: '100%', justifyContent: 'center' }} disabled={loading}>
            <ShieldCheck size={16} aria-hidden='true' />
            <span>{loading ? 'Creating Account...' : 'Create Account'}</span>
          </button>

          <div style={{ marginTop: '16px', textAlign: 'center', fontSize: '0.875rem' }}>
            <span style={{ color: 'var(--sb-text-secondary)' }}>Already registered? </span>
            <button
              type='button'
              className='btn-link'
              style={{ background: 'none', border: 'none', color: 'var(--sb-primary)', fontWeight: 600, cursor: 'pointer' }}
              onClick={() => { setMode('login'); setError(null); setSuccessMsg(null); }}
            >
              Sign in
            </button>
          </div>
        </form>
      )}

      {mode === 'forgot' && (
        <div style={{ marginTop: '16px' }}>
          {!resetToken ? (
            <form onSubmit={handleForgot}>
              <div className='form-group' style={{ marginBottom: '16px' }}>
                <label className='form-label' htmlFor='forgot-email'>
                  Your Account Email
                </label>
                <input
                  id='forgot-email'
                  type='email'
                  required
                  className='form-input'
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder='alice@domain.com'
                  disabled={loading}
                />
              </div>

              <button type='submit' className='btn btn-primary' style={{ width: '100%', justifyContent: 'center' }} disabled={loading}>
                <ArrowRight size={16} aria-hidden='true' />
                <span>{loading ? 'Requesting...' : 'Send Recovery Token'}</span>
              </button>
            </form>
          ) : (
            <form onSubmit={handleResetPassword}>
              <div className='form-group' style={{ marginBottom: '12px' }}>
                <label className='form-label' htmlFor='reset-token-input'>
                  Recovery Token
                </label>
                <input
                  id='reset-token-input'
                  type='text'
                  required
                  className='form-input'
                  value={resetToken}
                  onChange={(e) => setResetToken(e.target.value)}
                  disabled={loading}
                />
              </div>

              <div className='form-group' style={{ marginBottom: '16px' }}>
                <label className='form-label' htmlFor='reset-new-password'>
                  New Password (min 8 chars)
                </label>
                <input
                  id='reset-new-password'
                  type='password'
                  required
                  minLength={8}
                  className='form-input'
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder='••••••••••••'
                  disabled={loading}
                />
              </div>

              <button type='submit' className='btn btn-primary' style={{ width: '100%', justifyContent: 'center' }} disabled={loading}>
                <KeyRound size={16} aria-hidden='true' />
                <span>Set New Password</span>
              </button>
            </form>
          )}

          <div style={{ marginTop: '16px', textAlign: 'center', fontSize: '0.875rem' }}>
            <button
              type='button'
              className='btn-link'
              style={{ background: 'none', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer' }}
              onClick={() => { setMode('login'); setError(null); setSuccessMsg(null); }}
            >
              Back to sign in
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
