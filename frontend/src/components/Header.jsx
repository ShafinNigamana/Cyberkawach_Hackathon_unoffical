import React, { useState, useRef, useEffect } from 'react';
import { 
  Globe, 
  Moon, 
  Sun, 
  Shield, 
  ExternalLink, 
  ChevronDown,
  Menu,
  Activity,
  PhoneCall,
  AlertTriangle,
  FlaskConical,
  User,
  LogIn,
  Lock,
  Layers,
  Sparkles
} from 'lucide-react';
import EmergencyBanner from './EmergencyBanner';
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
  onToggleMobileMenu = () => {}
}) {
  const [statusExpanded, setStatusExpanded] = useState(false);
  const statusRef = useRef(null);
  const t = TRANSLATIONS[lang] || TRANSLATIONS.en;

  const activeModulesCount = healthData?.modules 
    ? Object.values(healthData.modules).filter(Boolean).length 
    : 11;

  // Close status dropdown when clicking outside
  useEffect(() => {
    function handleClickOutside(event) {
      if (statusRef.current && !statusRef.current.contains(event.target)) {
        setStatusExpanded(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const flowLabels = {
    home: 'Executive Overview',
    message: 'Message & SMS Phishing Triage',
    url: 'URL & Website Threat Inspector',
    screenshot: 'Optical Evidence & OCR Scanner',
    result: 'Forensic Intelligence Dossier'
  };

  return (
    <header className="w-full select-none" id="main-header">
      {/* ─── 1. Fixed Sovereign Tricolor Ribbon (Pinned to Top) ─── */}
      <div 
        className="fixed top-0 left-0 right-0 z-50 h-[3px] w-full flex overflow-hidden shadow-xs pointer-events-none" 
        aria-hidden="true"
      >
        <div className="h-full flex-1 bg-[#FF9933] relative overflow-hidden">
          <div className="absolute inset-0 bg-white/20 animate-tricolor-sweep motion-reduce:animate-none pointer-events-none" />
        </div>
        <div className="h-full flex-1 bg-white relative overflow-hidden">
          <div className="absolute inset-0 bg-slate-300/30 animate-tricolor-sweep motion-reduce:animate-none pointer-events-none" />
        </div>
        <div className="h-full flex-1 bg-[#138808] relative overflow-hidden">
          <div className="absolute inset-0 bg-white/20 animate-tricolor-sweep motion-reduce:animate-none pointer-events-none" />
        </div>
      </div>

      {/* ─── 2. Golden Hour Emergency Alert Banner ─── */}
      <div className="pt-[3px]">
        <EmergencyBanner lang={lang} />
      </div>

      {/* ─── 3. Top Command Bar ─── */}
      <div className="bg-white/85 dark:bg-night-900/85 backdrop-blur-xl border-b border-slate-200/80 dark:border-night-border/80 px-4 sm:px-6 py-3 transition-colors">
        <div className="flex items-center justify-between gap-4">
          {/* Left: Mobile Hamburger & Flow Breadcrumb */}
          <div className="flex items-center space-x-3">
            <button
              type="button"
              onClick={onToggleMobileMenu}
              className="lg:hidden p-2 rounded-xl text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-night-800 transition-colors cursor-pointer"
              aria-label="Open Navigation Menu"
            >
              <Menu className="w-5 h-5" />
            </button>

            {/* Breadcrumb path */}
            <div className="flex items-center space-x-2 text-xs">
              <span className="font-bold text-indigo-600 dark:text-violet-400">Cyber Kavach</span>
              <span className="text-slate-300 dark:text-slate-600">/</span>
              <span className="font-semibold text-slate-800 dark:text-slate-200">
                {flowLabels[currentFlow] || 'Triage'}
              </span>
            </div>
          </div>

          {/* Right: Institutional Utility Actions */}
          <div className="flex items-center space-x-2 sm:space-x-3 text-xs">
            {/* Language Selector Modal Trigger */}
            <button
              type="button"
              onClick={onOpenLanguageModal}
              className="flex items-center space-x-1.5 px-2.5 py-1.5 rounded-lg text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-night-800 font-medium transition-colors cursor-pointer"
              title="Select Language / भाषा चुनें"
            >
              <Globe className="w-3.5 h-3.5 text-indigo-500 dark:text-violet-400" />
              <span className="hidden sm:inline font-semibold">
                {lang === 'hi' ? 'हिन्दी' : lang === 'gu' ? 'ગુજરાતી' : lang === 'ta' ? 'தமிழ்' : lang === 'te' ? 'తెలుగు' : lang === 'bn' ? 'বাংলা' : 'English'}
              </span>
            </button>

            {/* Font Size Adjuster */}
            <div className="hidden md:flex items-center space-x-1 px-2 py-1 rounded-lg bg-slate-100/70 dark:bg-night-800/80 border border-slate-200/80 dark:border-night-border text-slate-600 dark:text-slate-400">
              <span className="text-[11px] font-bold select-none px-1">Aa</span>
              <select
                value={fontSize}
                onChange={(e) => onFontSizeChange(e.target.value)}
                className="bg-transparent text-xs font-semibold text-slate-800 dark:text-slate-200 focus:outline-none cursor-pointer border-0 py-0.5"
                aria-label="Adjust font scale"
              >
                <option value="normal" className="bg-white text-slate-900 dark:bg-night-900 dark:text-slate-100">Normal</option>
                <option value="large" className="bg-white text-slate-900 dark:bg-night-900 dark:text-slate-100">Large (+10%)</option>
                <option value="small" className="bg-white text-slate-900 dark:bg-night-900 dark:text-slate-100">Compact (-10%)</option>
              </select>
            </div>

            {/* Theme Toggle Button */}
            <button
              type="button"
              onClick={onThemeToggle}
              className="p-1.5 sm:px-2.5 sm:py-1.5 rounded-lg text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-night-800 transition-colors flex items-center space-x-1.5 cursor-pointer"
              title={isDark ? "Switch to Light Theme" : "Switch to Dark Theme"}
              aria-label="Toggle theme"
            >
              {isDark ? (
                <Sun className="w-4 h-4 text-amber-400" />
              ) : (
                <Moon className="w-4 h-4 text-slate-600" />
              )}
              <span className="hidden sm:inline font-medium">
                {isDark ? 'Light' : 'Dark'}
              </span>
            </button>

            {/* Methodology Modal Trigger */}
            <button
              type="button"
              onClick={onOpenMethodology}
              className="hidden lg:flex items-center space-x-1.5 px-2.5 py-1.5 rounded-lg text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-night-800 font-medium transition-colors cursor-pointer"
              title="Technical Methodology & Audit Matrix"
            >
              <FlaskConical className="w-3.5 h-3.5 text-indigo-500 dark:text-violet-400" />
              <span>{t.methodology || 'Methodology'}</span>
            </button>

            {/* Status Telemetry Pill with Popover */}
            <div className="relative" ref={statusRef}>
              <button
                type="button"
                onClick={() => setStatusExpanded(!statusExpanded)}
                className="inline-flex items-center space-x-2 px-3 py-1.5 rounded-xl border border-slate-200 dark:border-night-border bg-slate-50 dark:bg-night-800/80 text-slate-700 dark:text-slate-300 text-xs font-semibold hover:border-violet-500/50 transition-colors cursor-pointer shadow-2xs"
                aria-expanded={statusExpanded}
                aria-label="System status"
              >
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                </span>
                <span className="hidden sm:inline">{activeModulesCount}/11 Online</span>
                <ChevronDown className={`w-3.5 h-3.5 text-slate-400 transition-transform ${statusExpanded ? 'rotate-180' : ''}`} />
              </button>

              {/* Popover */}
              {statusExpanded && (
                <div 
                  className="absolute right-0 mt-2 w-72 sm:w-80 bg-white dark:bg-night-900 border border-slate-200 dark:border-night-border rounded-2xl shadow-2xl p-4 z-50 text-xs space-y-3"
                  role="region"
                  aria-label="System Architecture Status"
                >
                  <div className="flex items-center justify-between pb-2 border-b border-slate-100 dark:border-night-border/80">
                    <span className="font-bold text-slate-900 dark:text-white">Active Telemetry & Engines</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded-md bg-indigo-50 dark:bg-violet-950/80 text-indigo-700 dark:text-violet-300 font-bold border border-indigo-200 dark:border-violet-800">
                      v1.0 • Track S2
                    </span>
                  </div>

                  <div className="space-y-2.5">
                    <div className="flex items-start space-x-2.5">
                      <span className="w-2 h-2 rounded-full bg-emerald-500 mt-1 flex-shrink-0" />
                      <div>
                        <strong className="text-slate-900 dark:text-white block font-semibold">11 Engines Active</strong>
                        <p className="text-[11px] text-slate-500 dark:text-slate-400">Rule engine, Fast Laya, Safe Browsing, PhishTank, PhishStats, and Epistemic Bounds.</p>
                      </div>
                    </div>

                    <div className="flex items-start space-x-2.5">
                      <span className="w-2 h-2 rounded-full bg-emerald-500 mt-1 flex-shrink-0" />
                      <div>
                        <strong className="text-slate-900 dark:text-white block font-semibold">Zero-PII Memory Redaction</strong>
                        <p className="text-[11px] text-slate-500 dark:text-slate-400">Aadhaar, PAN & OTP numbers redacted in-memory prior to evaluation.</p>
                      </div>
                    </div>
                  </div>

                  <div className="pt-2 border-t border-slate-100 dark:border-night-border/80 flex items-center justify-between text-[11px]">
                    <span className="text-slate-500 dark:text-slate-400">I4C Partner Initiative</span>
                    <a 
                      href="/verification.html" 
                      target="_blank" 
                      rel="noreferrer"
                      className="text-indigo-600 dark:text-violet-400 font-bold hover:underline inline-flex items-center space-x-1"
                    >
                      <span>Run Audits</span>
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  </div>
                </div>
              )}
            </div>

            {/* Citizen Auth Button */}
            {!currentUser ? (
              <button
                type="button"
                onClick={() => onOpenAuthModal('Citizen authentication required to submit messages for forensic analysis.')}
                className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 dark:bg-gradient-to-r dark:from-indigo-600 dark:to-violet-600 text-white font-bold text-xs transition-all shadow-sm active:scale-95 cursor-pointer"
              >
                <LogIn className="w-3.5 h-3.5 text-violet-300" />
                <span className="hidden sm:inline">Sign In</span>
              </button>
            ) : (
              <button
                type="button"
                onClick={() => onOpenAuthModal(null, 'history')}
                className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-xl bg-slate-100 dark:bg-night-800 hover:bg-slate-200 dark:hover:bg-night-750 text-slate-800 dark:text-slate-200 font-bold text-xs border border-slate-200 dark:border-night-border transition-all cursor-pointer"
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
