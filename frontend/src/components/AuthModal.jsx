import React, { useState } from 'react';
import { X, Mail, Lock, User, ArrowRight, Loader2 } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext';

export const AuthModal = () => {
  const { authModalOpen, authModalTab, setAuthModalTab, closeAuthModal, login, signup } = useAuth();
  const { addToast } = useToast();

  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  if (!authModalOpen) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (authModalTab === 'signup' && username.trim().length < 3) {
      setError('Username must be at least 3 characters.');
      return;
    }
    if (!email.includes('@')) {
      setError('Please enter a valid email address.');
      return;
    }
    if (password.length < 6) {
      setError('Password must be at least 6 characters.');
      return;
    }

    try {
      setLoading(true);
      if (authModalTab === 'login') {
        await login(email, password);
        addToast('Signed in successfully.', 'success');
      } else {
        await signup(username, email, password);
        addToast('Account created and signed in.', 'success');
      }
      setUsername('');
      setEmail('');
      setPassword('');
    } catch (err) {
      console.error(err);
      const msg = err.response?.data?.error || err.response?.data?.message || 'Authentication failed. Please check your credentials.';
      setError(msg);
      addToast(msg, 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-backdrop" onClick={closeAuthModal}>
      <div className="modal-container" onClick={(e) => e.stopPropagation()}>
        {/* Header with Clean Tabs */}
        <div className="modal-header">
          <div style={{ display: 'flex', gap: '0.25rem', backgroundColor: 'var(--bg-subtle)', padding: '2px', borderRadius: 'var(--radius-xs)' }}>
            <button
              onClick={() => { setAuthModalTab('login'); setError(''); }}
              style={{
                padding: '0.35rem 0.85rem',
                borderRadius: 'var(--radius-xs)',
                fontSize: '0.8125rem',
                fontWeight: 600,
                backgroundColor: authModalTab === 'login' ? 'var(--bg-surface)' : 'transparent',
                color: authModalTab === 'login' ? 'var(--text-main)' : 'var(--text-secondary)',
                boxShadow: authModalTab === 'login' ? 'var(--shadow-xs)' : 'none',
              }}
            >
              Sign In
            </button>
            <button
              onClick={() => { setAuthModalTab('signup'); setError(''); }}
              style={{
                padding: '0.35rem 0.85rem',
                borderRadius: 'var(--radius-xs)',
                fontSize: '0.8125rem',
                fontWeight: 600,
                backgroundColor: authModalTab === 'signup' ? 'var(--bg-surface)' : 'transparent',
                color: authModalTab === 'signup' ? 'var(--text-main)' : 'var(--text-secondary)',
                boxShadow: authModalTab === 'signup' ? 'var(--shadow-xs)' : 'none',
              }}
            >
              Register
            </button>
          </div>

          <button onClick={closeAuthModal} className="btn-icon" aria-label="Close modal">
            <X size={16} />
          </button>
        </div>

        {/* Body */}
        <div className="modal-body">
          <div style={{ marginBottom: '1.25rem' }}>
            <h2 style={{ fontSize: '1.25rem', fontWeight: 800 }}>
              {authModalTab === 'login' ? 'Sign in to Podcaster' : 'Create a Creator Account'}
            </h2>
            <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
              {authModalTab === 'login'
                ? 'Access your dashboard, uploaded podcasts, and articles.'
                : 'Join the community to start publishing episodes and articles.'}
            </p>
          </div>

          {error && (
            <div style={{
              backgroundColor: 'var(--danger-bg)',
              color: 'var(--danger)',
              border: '1px solid #fca5a5',
              padding: '0.65rem 0.85rem',
              borderRadius: 'var(--radius-xs)',
              fontSize: '0.8125rem',
              marginBottom: '1rem',
              fontWeight: 500
            }}>
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit}>
            {authModalTab === 'signup' && (
              <div className="form-group">
                <label className="form-label">Username</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. alex_audio"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="form-input"
                />
              </div>
            )}

            <div className="form-group">
              <label className="form-label">Email Address</label>
              <input
                type="email"
                required
                placeholder="name@domain.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="form-input"
              />
            </div>

            <div className="form-group">
              <label className="form-label">Password</label>
              <input
                type="password"
                required
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="form-input"
              />
              {authModalTab === 'signup' && (
                <div className="form-helper">At least 6 characters.</div>
              )}
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn btn-primary btn-lg"
              style={{ width: '100%', marginTop: '0.5rem' }}
            >
              {loading ? (
                <>
                  <Loader2 size={16} className="spin" />
                  <span>Processing...</span>
                </>
              ) : (
                <span>{authModalTab === 'login' ? 'Sign In' : 'Create Account'}</span>
              )}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};
