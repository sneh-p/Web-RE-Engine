import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import {
  Binary,
  Layers,
  List,
  LogOut,
  HardDrive,
  Shield, Settings as SettingsIcon } from 'lucide-react';
import type { EngineStatus } from '@shared/types.js';
import { useAuth } from '../../context/AuthContext';

interface NavbarProps {
  engineStatus?: EngineStatus;
}

export const Navbar: React.FC<NavbarProps> = ({ engineStatus }) => {
  const { authenticated, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  const primaryEngines = [
    { label: 'radare2', on: !!engineStatus?.radare2 },
    { label: 'YARA', on: !!engineStatus?.yara },
    { label: 'Browser', on: !!engineStatus?.playwright },
  ];
  const secondaryEngines = [
    { label: 'Ghidra decompiler (r2ghidra)', on: !!engineStatus?.r2ghidra },
    { label: 'UPX unpacker', on: !!engineStatus?.upx },
    { label: 'capa capability detection', on: !!engineStatus?.capa },
    { label: 'pycdc Python decompiler', on: !!engineStatus?.pycdc },
    { label: 'ILSpy .NET decompiler', on: !!engineStatus?.ilspy },
    { label: 'jadx/apktool (Android)', on: !!engineStatus?.apktool },
    { label: 'Ghidra headless', on: !!engineStatus?.ghidra },
    { label: 'adb', on: !!engineStatus?.adb },
  ];

  return (
    <header className="border-b border-rea-border bg-rea-surface px-6 py-4 flex items-center justify-between">
      <div className="flex items-center space-x-3">
        <NavLink to="/" className="flex items-center space-x-2">
          <div className="bg-rea-accent p-2 rounded-lg text-white">
            <Binary className="w-5 h-5" />
          </div>
          <span className="font-bold text-lg text-white tracking-wide whitespace-nowrap">Web RE Engine</span>
        </NavLink>
        <span className="text-xs px-2 py-0.5 rounded bg-rea-border text-rea-muted uppercase tracking-wider">
          Web UI
        </span>
      </div>

      <nav className="flex items-center space-x-6">
        <NavLink
          to="/"
          className={({ isActive }) =>
            `flex items-center space-x-2 text-sm font-medium transition ${
              isActive ? 'text-white' : 'text-rea-muted hover:text-white'
            }`
          }
        >
          <Layers className="w-4 h-4" />
          <span>New Analysis</span>
        </NavLink>

        <NavLink
          to="/jobs"
          className={({ isActive }) =>
            `flex items-center space-x-2 text-sm font-medium transition ${
              isActive ? 'text-white' : 'text-rea-muted hover:text-white'
            }`
          }
        >
          <List className="w-4 h-4" />
          <span>Jobs & History</span>
        </NavLink>

        <NavLink
          to="/settings"
          className={({ isActive }) =>
            `flex items-center space-x-2 text-sm font-medium transition ${
              isActive ? 'text-white' : 'text-rea-muted hover:text-white'
            }`
          }
        >
          <SettingsIcon className="w-4 h-4" />
          <span>Settings</span>
        </NavLink>
      </nav>

      {/* Engine Status & Auth Indicators */}
      <div className="flex items-center space-x-4 text-xs">
        <div className="flex items-center space-x-3">
          <span className="text-rea-muted hidden md:inline">Engines:</span>
          <div className="flex items-center space-x-1.5" title="JavaScript Analysis (Built-in)">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            <span className="text-rea-text">JS</span>
          </div>
          {primaryEngines.map((e) => (
            <div key={e.label} className="flex items-center space-x-1.5" title={`${e.label}: ${e.on ? 'available' : 'not installed'}`}>
              <span className={`w-2 h-2 rounded-full ${e.on ? 'bg-emerald-500' : 'bg-rea-muted'}`}></span>
              <span className="text-rea-text">{e.label}</span>
            </div>
          ))}
          <div
            className="hidden lg:flex items-center space-x-1 text-rea-muted cursor-help"
            title={secondaryEngines.map((e) => `${e.on ? '✓' : '✗'} ${e.label}`).join('\n')}
          >
            <span>
              +{secondaryEngines.filter((e) => e.on).length}/{secondaryEngines.length} tools
            </span>
          </div>
          <div
            className="flex items-center space-x-1.5"
            title={engineStatus?.sandbox ? 'Sandbox active (bwrap)' : 'Sandbox offline (unsandboxed)'}
          >
            <span
              className={`w-2 h-2 rounded-full ${
                engineStatus?.sandbox ? 'bg-emerald-500' : 'bg-amber-500'
              }`}
            ></span>
            <span className="text-rea-text">Sandbox</span>
          </div>
        </div>

        {engineStatus?.uploadsBytes !== undefined && (
          <div
            className="hidden lg:flex items-center space-x-1.5 border-l border-rea-border pl-3 text-rea-muted"
            title="Uploads directory disk usage (cached up to 10m)"
          >
            <HardDrive className="w-3.5 h-3.5" />
            <span>{(engineStatus.uploadsBytes / (1024 * 1024)).toFixed(1)} MB</span>
          </div>
        )}

        {authenticated && (
          <div className="border-l border-rea-border pl-3">
            <button
              onClick={handleLogout}
              className="flex items-center space-x-1.5 py-1 px-2.5 rounded bg-rea-border/60 hover:bg-rea-border text-rea-muted hover:text-white transition"
              title="Logout from admin session"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span>Logout</span>
            </button>
          </div>
        )}
      </div>
    </header>
  );
};
