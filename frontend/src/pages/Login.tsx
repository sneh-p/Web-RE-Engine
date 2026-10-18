import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Lock, AlertTriangle, ShieldCheck, Key } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export const Login: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { authenticated, authConfigured, login } = useAuth();

  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (authenticated) {
      const from = (location.state as any)?.from?.pathname || '/';
      navigate(from, { replace: true });
    }
  }, [authenticated, navigate, location]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!password) return;

    setIsSubmitting(true);
    setError(null);

    try {
      await login(password);
      const from = (location.state as any)?.from?.pathname || '/';
      navigate(from, { replace: true });
    } catch (err: any) {
      setError(err.message || 'Login failed');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="flex items-center justify-center min-h-[calc(100vh-140px)] px-4">
      <div className="w-full max-w-md bg-rea-surface border border-rea-border rounded-xl p-8 shadow-2xl">
        <div className="flex flex-col items-center mb-6">
          <div className="bg-rea-accent p-3 rounded-xl text-white mb-3 shadow-lg">
            <Lock className="w-6 h-6" />
          </div>
          <h1 className="text-xl font-bold text-white tracking-wide">Web RE Engine</h1>
          <p className="text-xs text-rea-muted mt-1">Admin Authentication</p>
        </div>

        {!authConfigured && (
          <div className="mb-6 p-4 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-300 text-sm flex items-start space-x-3">
            <AlertTriangle className="w-5 h-5 flex-shrink-0 text-amber-400 mt-0.5" />
            <div>
              <p className="font-semibold text-amber-200">Authentication Not Configured</p>
              <p className="mt-1 text-xs leading-relaxed text-amber-300/90 font-mono">
                Authentication not configured. Run: cd backend && npm run set-password
              </p>
            </div>
          </div>
        )}

        {error && (
          <div className="mb-6 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-rea-muted mb-2">
              Admin Password
            </label>
            <div className="relative">
              <input
                type="password"
                required
                disabled={!authConfigured || isSubmitting}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder={authConfigured ? 'Enter admin password' : 'Set password in backend first'}
                className="w-full bg-rea-bg border border-rea-border rounded-lg px-4 py-2.5 text-sm text-rea-text placeholder-rea-muted focus:outline-none focus:border-rea-accent disabled:opacity-50 disabled:cursor-not-allowed pl-10"
              />
              <Key className="w-4 h-4 text-rea-muted absolute left-3.5 top-3" />
            </div>
          </div>

          <button
            type="submit"
            disabled={!authConfigured || isSubmitting || !password}
            className="w-full py-2.5 px-4 rounded-lg bg-rea-accent hover:bg-rea-accent/90 text-white font-medium text-sm transition flex items-center justify-center space-x-2 shadow-md disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <ShieldCheck className="w-4 h-4" />
            <span>{isSubmitting ? 'Authenticating...' : 'Sign In'}</span>
          </button>
        </form>
      </div>
    </div>
  );
};
