import React from 'react';
import { Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Navbar } from './components/layout/Navbar';
import { Home } from './pages/Home';
import { JobDetails } from './pages/JobDetails';
import { JobList } from './pages/JobList';
import { Login } from './pages/Login';
import { Compare } from './pages/Compare';
import { Settings } from './pages/Settings';
import { fetchStatus } from './api/client';
import { AuthProvider, useAuth } from './context/AuthContext';

const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { authenticated, loading } = useAuth();
  const location = useLocation();

  if (loading) {
    return (
      <div className="flex-1 flex items-center justify-center p-12 text-rea-muted text-sm">
        Loading authentication...
      </div>
    );
  }

  if (!authenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return <>{children}</>;
};

const AppContent: React.FC = () => {
  const { authenticated } = useAuth();

  const { data: engineStatus } = useQuery({
    queryKey: ['engineStatus'],
    queryFn: fetchStatus,
    enabled: Boolean(authenticated),
    refetchInterval: 30000,
  });

  return (
    <div className="min-h-screen flex flex-col bg-rea-bg text-rea-text">
      <Navbar engineStatus={engineStatus} />
      <main className="flex-1">
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <Home />
              </ProtectedRoute>
            }
          />
          <Route
            path="/jobs"
            element={
              <ProtectedRoute>
                <JobList />
              </ProtectedRoute>
            }
          />
          <Route
            path="/jobs/:id"
            element={
              <ProtectedRoute>
                <JobDetails />
              </ProtectedRoute>
            }
          />
          <Route
            path="/compare"
            element={
              <ProtectedRoute>
                <Compare />
              </ProtectedRoute>
            }
          />
          <Route
            path="/settings"
            element={
              <ProtectedRoute>
                <Settings />
              </ProtectedRoute>
            }
          />
        </Routes>
      </main>
      <footer className="border-t border-rea-border py-6 text-center text-xs text-rea-muted bg-rea-surface/40">
        Web RE Engine &bull; Web-based reverse engineering &bull; Built with React & Node.js
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
