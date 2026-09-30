import React, { useState } from 'react';
import { 
  Shield, 
  Home, 
  MessageSquare, 
  Globe, 
  Camera, 
  ChevronLeft, 
  ChevronRight, 
  Lock, 
  User, 
  History, 
  LogIn, 
  Activity, 
  FlaskConical, 
  ExternalLink,
  Sparkles,
  Zap,
  CheckCircle2,
  FileText
} from 'lucide-react';
import { PRESET_SCENARIOS } from '../data/presets';
import { t, TRANSLATIONS } from '../i18n/translations';

export default function Sidebar({
  currentFlow,
  onSelectFlow,
  currentUser,
  onOpenAuthModal,
  healthData,
  isCollapsed,
  onToggleCollapse,
  isMobileOpen,
  onCloseMobile,
  onSelectPreset,
  lang = 'en'
}) {
  const [benchmarksOpen, setBenchmarksOpen] = useState(false);
  const activeModulesCount = healthData?.modules 
    ? Object.values(healthData.modules).filter(Boolean).length 
    : 11;

  const handleNav = (flow) => {
    if (!currentUser && flow !== 'home') {
      onOpenAuthModal(`Citizen authentication required to access the ${flow} triage engine.`, 'login', flow);
      return;
    }
    onSelectFlow(flow);
    if (isMobileOpen && onCloseMobile) {
      onCloseMobile();
    }
  };

  const navItems = [
    { id: 'home', label: 'Command Center', icon: Home, desc: 'Executive Overview' },
    { id: 'message', label: 'Message & SMS', icon: MessageSquare, desc: 'Coercive Phishing Triage' },
    { id: 'url', label: 'URL & Website', icon: Globe, desc: 'Domain Threat Intelligence' },
    { id: 'screenshot', label: 'Screenshot OCR', icon: Camera, desc: 'Visual Evidence Scanner' },
  ];

  return (
    <>
      {/* Mobile Backdrop Overlay */}
      {isMobileOpen && (
        <div 
          onClick={onCloseMobile}
          className="fixed inset-0 bg-slate-950/70 backdrop-blur-sm z-40 lg:hidden transition-opacity"
          aria-hidden="true"
        />
      )}

      {/* Main Command Center Sidebar Container */}
      <aside 
        className={`fixed top-0 bottom-0 left-0 z-50 flex flex-col bg-white/95 dark:bg-night-900/95 backdrop-blur-2xl border-r border-slate-200/90 dark:border-night-border transition-all duration-300 ease-in-out select-none shadow-xl lg:shadow-none ${
          isMobileOpen ? 'translate-x-0 w-72' : '-translate-x-full lg:translate-x-0'
        } ${isCollapsed ? 'lg:w-[76px]' : 'lg:w-[268px]'}`}
        aria-label="Command Center Sidebar"
      >
        {/* Brand & Logo Header */}
        <div className="h-16 flex items-center justify-between px-4 border-b border-slate-200/80 dark:border-night-border/80 flex-shrink-0">
          <div 
            onClick={() => handleNav('home')} 
            className="flex items-center space-x-3 cursor-pointer group overflow-hidden"
            title="Cyber Fraud Guardian Home"
          >
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-indigo-600 via-violet-600 to-purple-500 p-[1.5px] shadow-luxury-glow flex-shrink-0 group-hover:scale-105 transition-transform">
              <div className="w-full h-full bg-slate-900 rounded-[10px] flex items-center justify-center">
                <Shield className="w-5 h-5 text-violet-300" strokeWidth={2.2} />
              </div>
            </div>

            {(!isCollapsed || isMobileOpen) && (
              <div className="flex flex-col min-w-0 transition-opacity duration-200">
                <div className="flex items-center space-x-1.5">
                  <span className="text-sm font-black tracking-tight text-slate-900 dark:text-white leading-tight">
                    CYBER<span className="text-indigo-600 dark:text-violet-400">KAWACH</span>
                  </span>
                  <span className="text-[9px] font-mono px-1 py-0.2 rounded bg-indigo-50 dark:bg-violet-950/80 text-indigo-700 dark:text-violet-300 font-bold border border-indigo-200 dark:border-violet-800">
                    S2
                  </span>
                </div>
                <span className="text-[10px] text-slate-500 dark:text-slate-400 font-medium truncate">
                  National Triage Console
                </span>
              </div>
            )}
          </div>

          {/* Desktop Collapse / Expand Toggle Button */}
          <button
            type="button"
            onClick={onToggleCollapse}
            className="hidden lg:flex items-center justify-center w-7 h-7 rounded-lg text-slate-400 hover:text-slate-800 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-night-800 transition-colors cursor-pointer"
            title={isCollapsed ? "Expand Sidebar" : "Collapse Sidebar"}
            aria-label="Toggle Sidebar width"
          >
            {isCollapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>
        </div>

        {/* Scrollable Navigation Body */}
        <div className="flex-1 overflow-y-auto px-3 py-4 space-y-6 scrollbar-none">
          {/* Main Navigation Section */}
          <div className="space-y-1">
            {(!isCollapsed || isMobileOpen) && (
              <div className="px-3 pb-1 text-[10px] font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                Triage Engines
              </div>
            )}

            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = currentFlow === item.id;
              const isLocked = !currentUser && item.id !== 'home';

              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => handleNav(item.id)}
                  className={`w-full group flex items-center space-x-3 px-3 py-2.5 rounded-xl text-xs font-semibold transition-all duration-200 cursor-pointer text-left relative ${
                    isActive
                      ? 'bg-gradient-to-r from-indigo-600 to-violet-600 text-white shadow-luxury-glow'
                      : 'text-slate-600 dark:text-slate-300 hover:bg-slate-100/90 dark:hover:bg-night-800 hover:text-slate-950 dark:hover:text-white'
                  }`}
                  title={item.label}
                >
                  <div className={`p-1.5 rounded-lg transition-colors flex-shrink-0 ${
                    isActive 
                      ? 'bg-white/20 text-white' 
                      : 'bg-slate-100 dark:bg-night-800/80 text-slate-500 dark:text-slate-400 group-hover:text-indigo-600 dark:group-hover:text-violet-400'
                  }`}>
                    <Icon className="w-4 h-4" />
                  </div>

                  {(!isCollapsed || isMobileOpen) && (
                    <div className="flex-1 min-w-0 flex items-center justify-between">
                      <div className="flex flex-col">
                        <span className="truncate">{item.label}</span>
                        <span className={`text-[10px] font-normal truncate ${
                          isActive ? 'text-indigo-100' : 'text-slate-400 dark:text-slate-500'
                        }`}>
                          {item.desc}
                        </span>
                      </div>
                      {isLocked && (
                        <Lock className="w-3 h-3 text-slate-400 dark:text-slate-500 ml-1 flex-shrink-0" />
                      )}
                    </div>
                  )}

                  {/* Active Indicator Bar on collapsed view */}
                  {isCollapsed && !isMobileOpen && isActive && (
                    <div className="absolute right-1 top-2.5 bottom-2.5 w-1 rounded-full bg-violet-400" />
                  )}
                </button>
              );
            })}
          </div>

          {/* Benchmark Scenarios Section */}
          {(!isCollapsed || isMobileOpen) && (
            <div className="space-y-2 pt-2 border-t border-slate-100 dark:border-night-border/70">
              <div className="flex items-center justify-between px-3 text-[10px] font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                <span className="flex items-center space-x-1.5">
                  <FlaskConical className="w-3 h-3 text-indigo-500" />
                  <span>Benchmark Scenarios</span>
                </span>
              </div>

              <div className="space-y-1">
                {PRESET_SCENARIOS.slice(0, 4).map((preset) => (
                  <button
                    key={preset.id}
                    type="button"
                    onClick={() => {
                      if (onSelectPreset) {
                        onSelectPreset(preset);
                        if (isMobileOpen && onCloseMobile) onCloseMobile();
                      }
                    }}
                    className="w-full text-left px-3 py-1.5 rounded-lg text-[11px] text-slate-600 dark:text-slate-300 hover:text-indigo-600 dark:hover:text-violet-300 hover:bg-slate-100 dark:hover:bg-night-800 transition-colors flex items-center justify-between group cursor-pointer"
                    title={preset.title}
                  >
                    <span className="truncate font-medium">{preset.title}</span>
                    <span className="text-[9px] font-mono px-1 rounded bg-slate-100 dark:bg-night-800 text-slate-400 group-hover:text-indigo-500 flex-shrink-0 ml-1">
                      Test
                    </span>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Verification & Legal Dossier */}
          {(!isCollapsed || isMobileOpen) && (
            <div className="space-y-2 pt-2 border-t border-slate-100 dark:border-night-border/70">
              <div className="px-3 text-[10px] font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                Forensic Audits
              </div>
              <a
                href="/verification.html"
                target="_blank"
                rel="noreferrer"
                className="flex items-center justify-between px-3 py-2 rounded-xl text-xs text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-night-800 hover:text-indigo-600 dark:hover:text-violet-300 transition-colors border border-dashed border-slate-200 dark:border-night-border"
              >
                <div className="flex items-center space-x-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" />
                  <span className="font-semibold">Run Test Matrix</span>
                </div>
                <ExternalLink className="w-3 h-3 text-slate-400" />
              </a>
            </div>
          )}
        </div>

        {/* Footer Station: Citizen Account & System Telemetry */}
        <div className="p-3 border-t border-slate-200/90 dark:border-night-border flex flex-col space-y-2 bg-slate-50/60 dark:bg-night-950/60 flex-shrink-0">
          {/* Citizen Auth Pill */}
          {!currentUser ? (
            <button
              type="button"
              onClick={() => onOpenAuthModal('Please sign in or register to access verified forensic threat triage.')}
              className={`flex items-center rounded-xl bg-slate-900 hover:bg-slate-800 dark:bg-gradient-to-r dark:from-indigo-600 dark:to-violet-600 text-white text-xs font-bold transition-all shadow-sm active:scale-95 cursor-pointer ${
                isCollapsed && !isMobileOpen ? 'justify-center p-2.5' : 'justify-between px-3 py-2'
              }`}
              title="Citizen Sign In"
            >
              <div className="flex items-center space-x-2 min-w-0">
                <LogIn className="w-4 h-4 flex-shrink-0 text-violet-300" />
                {(!isCollapsed || isMobileOpen) && (
                  <span className="truncate">Citizen Sign In</span>
                )}
              </div>
              {(!isCollapsed || isMobileOpen) && (
                <span className="text-[10px] opacity-75 font-normal">Auth</span>
              )}
            </button>
          ) : (
            <button
              type="button"
              onClick={() => onOpenAuthModal(null, 'history')}
              className={`flex items-center rounded-xl border border-slate-200 dark:border-night-border bg-white dark:bg-night-850 hover:border-violet-500/50 text-slate-800 dark:text-slate-200 text-xs font-semibold transition-all cursor-pointer shadow-2xs ${
                isCollapsed && !isMobileOpen ? 'justify-center p-2.5' : 'justify-between px-3 py-2'
              }`}
              title="Citizen Profile & My Past Checks"
            >
              <div className="flex items-center space-x-2 min-w-0">
                <div className="w-5 h-5 rounded-full bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 flex items-center justify-center text-[10px] font-bold flex-shrink-0">
                  {currentUser.display_name ? currentUser.display_name[0].toUpperCase() : 'U'}
                </div>
                {(!isCollapsed || isMobileOpen) && (
                  <span className="truncate text-xs font-bold">
                    {currentUser.display_name?.split(' ')[0] || currentUser.email.split('@')[0]}
                  </span>
                )}
              </div>
              {(!isCollapsed || isMobileOpen) && (
                <History className="w-3.5 h-3.5 text-indigo-500" />
              )}
            </button>
          )}

          {/* System Telemetry Pulse */}
          <div className={`flex items-center text-[11px] text-slate-500 dark:text-slate-400 pt-1 ${
            isCollapsed && !isMobileOpen ? 'justify-center' : 'justify-between px-1'
          }`}>
            <div className="flex items-center space-x-1.5" title={`${activeModulesCount} Forensic Defense Modules Active`}>
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </span>
              {(!isCollapsed || isMobileOpen) && (
                <span className="font-mono text-[10px] font-medium text-slate-600 dark:text-slate-400">
                  {activeModulesCount}/11 Online
                </span>
              )}
            </div>

            {(!isCollapsed || isMobileOpen) && (
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-200/70 dark:bg-night-800 text-slate-600 dark:text-slate-400">
                0-PII
              </span>
            )}
          </div>
        </div>
      </aside>
    </>
  );
}
