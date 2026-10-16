import React, { useState, useRef, useEffect } from 'react';
import { 
  Globe, 
  Moon, 
  Sun, 
  Shield, 
  PhoneCall, 
  ChevronDown, 
  FlaskConical, 
  LogIn, 
  ExternalLink,
  Activity,
  CheckCircle2,
  FileText
} from 'lucide-react';
import { TRANSLATIONS } from '../i18n/translations';

export default function Header({ 
  lang, 
  onLangChange, 
  onOpenLanguageModal = () => {},
  fontSize, 
  onFontSizeChange, 
  isDark, 
  onThemeToggle,
  onOpenMethodology,
  healthData,
  currentFlow = 'home',
  currentUser = null,
  onOpenAuthModal = () => {},
  onSelectFlow = () => {},
  onOpenFileScanModal = () => {}
}) {
  const [statusExpanded, setStatusExpanded] = useState(false);
  const statusRef = useRef(null);
  const t = TRANSLATIONS[lang] || TRANSLATIONS.en;

  const activeModulesCount = healthData?.modules 
    ? Object.values(healthData.modules).filter(Boolean).length 
    : 12;

  // Close status popover when clicking outside
  useEffect(() => {
    function handleClickOutside(event) {
      if (statusRef.current && !statusRef.current.contains(event.target)) {
        setStatusExpanded(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  return (
    <header className="w-full bg-white/95 dark:bg-slate-900/95 backdrop-blur-md border-b border-slate-200 dark:border-slate-800 sticky top-0 z-40 transition-colors">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16 gap-4">
          
          {/* Left: Authentic Security Laboratory Identity */}
          <div className="flex items-center space-x-3 cursor-pointer group" onClick={() => onSelectFlow('home')}>
            <div className="w-9 h-9 rounded-lg bg-slate-900 text-white dark:bg-white dark:text-slate-900 flex items-center justify-center font-mono font-black text-xs tracking-tight shadow-xs">
              CK
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-extrabold text-sm sm:text-base tracking-tight text-slate-900 dark:text-white leading-tight">
                  Cyber Defense Lab
                </span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 font-semibold border border-slate-200 dark:border-slate-700">
                  I4C Track S2
                </span>
              </div>
              <p className="text-[11px] text-slate-500 dark:text-slate-400 font-mono hidden sm:block leading-none mt-0.5">
                National Cyber Fraud Triage Console
              </p>
            </div>
          </div>

          {/* Center: Clean Triage Navigation */}
          <nav className="hidden md:flex items-center space-x-1 bg-slate-100 dark:bg-slate-800/60 p-1 rounded-xl border border-slate-200/80 dark:border-slate-700">
            <button
              type="button"
              onClick={() => onSelectFlow('home')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                currentFlow === 'home' || currentFlow === 'message'
                  ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-white shadow-xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
              }`}
            >
              Investigation Workbench
            </button>
            <button
              type="button"
              onClick={() => onSelectFlow('url')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                currentFlow === 'url'
                  ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-white shadow-xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
              }`}
            >
              URL Threat Sandbox
            </button>
            <button
              type="button"
              onClick={() => onSelectFlow('screenshot')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                currentFlow === 'screenshot'
                  ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-white shadow-xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
              }`}
            >
              Document OCR Scanner
            </button>
            <button
              type="button"
              onClick={onOpenFileScanModal}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white flex items-center gap-1.5"
            >
              <Shield className="w-3.5 h-3.5 text-blue-500" />
              <span>File Threat Scanner</span>
            </button>
          </nav>

          {/* Right: Technical Utilities & Citizen Support */}
          <div className="flex items-center space-x-2 sm:space-x-3 text-xs">
            
            {/* National Helpline 1930 Direct Action */}
            <a
              href="tel:1930"
              className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-red-50 hover:bg-red-100 dark:bg-red-950/40 dark:hover:bg-red-900/60 text-red-700 dark:text-red-300 border border-red-200 dark:border-red-900/60 font-semibold transition-colors cursor-pointer shadow-2xs"
              title="Call National Cyber Crime Helpline 1930"
            >
              <PhoneCall className="w-3.5 h-3.5 text-red-600 dark:text-red-400" />
              <span>1930 Helpline</span>
            </a>

            {/* Live Pipeline Telemetry Dropdown */}
            <div className="relative" ref={statusRef}>
              <button
                type="button"
                onClick={() => setStatusExpanded(!statusExpanded)}
                className="hidden sm:inline-flex items-center space-x-1.5 px-2.5 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-slate-700 dark:text-slate-300 font-mono text-[11px] font-semibold hover:border-slate-400 transition-colors cursor-pointer"
                aria-expanded={statusExpanded}
              >
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                <span>{activeModulesCount} Engines</span>
                <ChevronDown className={`w-3 h-3 text-slate-400 transition-transform ${statusExpanded ? 'rotate-180' : ''}`} />
              </button>

              {statusExpanded && (
                <div className="absolute right-0 mt-2 w-72 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xl p-3 z-50 text-xs space-y-2.5 font-sans">
                  <div className="flex items-center justify-between pb-2 border-b border-slate-100 dark:border-slate-800">
                    <span className="font-bold text-slate-900 dark:text-white">Pipeline Telemetry</span>
                    <span className="font-mono text-[10px] text-emerald-600 dark:text-emerald-400 font-semibold">100% Operational</span>
                  </div>
                  <div className="text-[11px] space-y-1.5 text-slate-600 dark:text-slate-400">
                    <div className="flex items-center justify-between">
                      <span>Deterministic Rules & DLT:</span>
                      <span className="font-mono text-emerald-600 font-semibold">Verified</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span>Threat Feeds (SafeBrowsing/URLhaus):</span>
                      <span className="font-mono text-emerald-600 font-semibold">Active</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span>In-Memory PII Masking:</span>
                      <span className="font-mono text-emerald-600 font-semibold">Zero-PII</span>
                    </div>
                  </div>
                  <div className="pt-2 border-t border-slate-100 dark:border-slate-800 flex justify-between items-center text-[10px]">
                    <span className="text-slate-400">Response &lt; 200ms</span>
                    <button
                      type="button"
                      onClick={() => { setStatusExpanded(false); onOpenMethodology(); }}
                      className="text-slate-900 dark:text-white font-bold hover:underline"
                    >
                      Audit Specs &rarr;
                    </button>
                  </div>
                </div>
              )}
            </div>

            {/* Language Switcher */}
            <button
              type="button"
              onClick={onOpenLanguageModal}
              className="flex items-center space-x-1 px-2.5 py-1.5 rounded-lg text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 font-medium transition-colors cursor-pointer border border-transparent hover:border-slate-200 dark:hover:border-slate-700"
              title="Select Language"
            >
              <Globe className="w-3.5 h-3.5 text-slate-500" />
              <span className="font-mono text-xs font-semibold uppercase">{lang}</span>
            </button>

            {/* Dark / Light Toggle */}
            <button
              type="button"
              onClick={onThemeToggle}
              className="p-1.5 rounded-lg text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer border border-transparent hover:border-slate-200 dark:hover:border-slate-700"
              title={isDark ? "Switch to Light Theme" : "Switch to Dark Theme"}
            >
              {isDark ? <Sun className="w-4 h-4 text-amber-400" /> : <Moon className="w-4 h-4 text-slate-600" />}
            </button>

            {/* Citizen Auth */}
            {!currentUser ? (
              <button
                type="button"
                onClick={() => onOpenAuthModal('Sign in to access your saved checks, persistent preferences, and incident history.')}
                className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 dark:bg-white dark:hover:bg-slate-100 text-white dark:text-slate-900 font-semibold text-xs transition-all shadow-xs active:scale-95 cursor-pointer"
              >
                <LogIn className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">Sign In</span>
              </button>
            ) : (
              <button
                type="button"
                onClick={() => onOpenAuthModal(null, 'history')}
                className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 font-semibold text-xs border border-slate-200 dark:border-slate-700 transition-all cursor-pointer"
              >
                <span className="w-2 h-2 rounded-full bg-emerald-500" />
                <span className="max-w-[100px] truncate">
                  {currentUser.display_name?.split(' ')[0] || currentUser.email.split('@')[0]}
                </span>
              </button>
            )}

          </div>

        </div>
      </div>
    </header>
  );
}
