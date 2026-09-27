import React, { useState, useRef, useEffect } from 'react';
import { 
  Globe, 
  Moon, 
  Sun, 
  Shield, 
  ExternalLink, 
  ChevronDown,
  MessageSquare, 
  Camera, 
  Home,
  User,
  LogIn,
  Lock
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
  onSelectFlow = () => {},
  currentUser = null,
  onOpenAuthModal = () => {}
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

  return (
    <header className="w-full select-none" id="main-header">
      {/* ─── 1. Fixed 3-4px Tricolor Ribbon Pinned to Very Top (Persistent on Scroll) ─── */}
      <div 
        className="fixed top-0 left-0 right-0 z-50 h-[3.5px] w-full flex overflow-hidden shadow-xs pointer-events-none" 
        aria-hidden="true"
      >
        <div className="h-full flex-1 bg-[#FF9933] relative overflow-hidden">
          <div className="absolute inset-0 bg-white/25 animate-tricolor-sweep motion-reduce:animate-none pointer-events-none" />
        </div>
        <div className="h-full flex-1 bg-white relative overflow-hidden">
          <div className="absolute inset-0 bg-slate-200/40 animate-tricolor-sweep motion-reduce:animate-none pointer-events-none" />
        </div>
        <div className="h-full flex-1 bg-[#138808] relative overflow-hidden">
          <div className="absolute inset-0 bg-white/25 animate-tricolor-sweep motion-reduce:animate-none pointer-events-none" />
        </div>
      </div>

      {/* ─── 2. Critical Fraud Advisory Banner (Directly Below Tricolor Strip, Above Header/Nav) ─── */}
      <div className="pt-[3.5px]">
        <EmergencyBanner lang={lang} />
      </div>

      {/* ─── 3. Utility Bar: Text-Only, No Colored Pill Badges ─── */}
      <div className="bg-slate-50 dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 text-xs py-1.5 px-4 sm:px-6 transition-colors">
        <div className="max-w-7xl mx-auto flex items-center justify-between gap-3 flex-wrap">
          {/* Left: Government of India label */}
          <div className="flex items-center space-x-2">
            <svg viewBox="0 0 24 24" width="15" height="15" fill="currentColor" className="text-slate-700 dark:text-slate-300 flex-shrink-0" aria-hidden="true">
              <circle cx="12" cy="12" r="10" fill="none" stroke="currentColor" strokeWidth="1.5" />
              <circle cx="12" cy="12" r="2" fill="currentColor" />
              <path d="M12 2v20M2 12h20M4.93 4.93l14.14 14.14M4.93 19.07L19.07 4.93M8.46 2.54l7.08 18.92M2.54 8.46l18.92 7.08M15.54 2.54L8.46 21.46M2.54 15.54l18.92-7.08" stroke="currentColor" strokeWidth="0.8" />
            </svg>
            <div className="flex items-center space-x-1.5 font-medium tracking-wide">
              <span className="font-bold text-slate-900 dark:text-white">{t.portalGovHi || 'भारत सरकार'}</span>
              <span className="text-slate-400">|</span>
              <span className="font-semibold text-slate-800 dark:text-slate-200">{t.portalGov || 'Government of India'}</span>
            </div>
          </div>

          {/* Right: Text-Only Utility Controls (No colored pill badges) */}
          <div className="flex items-center space-x-3 text-xs">
            {/* Language Dropdown */}
            <div className="flex items-center space-x-1.5">
              <button
                type="button"
                onClick={onOpenLanguageModal}
                className="flex items-center space-x-1 text-slate-700 dark:text-slate-300 hover:text-cyan-600 dark:hover:text-cyan-400 font-semibold cursor-pointer py-0.5"
                title="Select Language / भाषा चुनें"
              >
                <Globe className="w-3.5 h-3.5 text-cyan-500" />
                <span className="text-[11px] underline decoration-cyan-500/50 underline-offset-2">
                  {lang === 'hi' ? 'हिन्दी' : lang === 'gu' ? 'ગુજરાતી' : lang === 'ta' ? 'தமிழ்' : lang === 'te' ? 'తెలుగు' : lang === 'bn' ? 'বাংলা' : 'English'}
                </span>
              </button>

              <select 
                value={lang} 
                onChange={(e) => onLangChange(e.target.value)}
                className="bg-transparent text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white text-xs font-medium focus:outline-none cursor-pointer py-0.5 border-0"
                aria-label="Select Portal Language"
              >
                <option value="en" className="bg-white text-slate-900 dark:bg-slate-900 dark:text-slate-100">English</option>
                <option value="hi" className="bg-white text-slate-900 dark:bg-slate-900 dark:text-slate-100">हिंदी (Hindi)</option>
                <option value="gu" className="bg-white text-slate-900 dark:bg-slate-900 dark:text-slate-100">ગુજરાતી (Gujarati)</option>
                <option value="ta" className="bg-white text-slate-900 dark:bg-slate-900 dark:text-slate-100">தமிழ் (Tamil)</option>
                <option value="te" className="bg-white text-slate-900 dark:bg-slate-900 dark:text-slate-100">తెలుగు (Telugu)</option>
                <option value="bn" className="bg-white text-slate-900 dark:bg-slate-900 dark:text-slate-100">বাংলা (Bengali)</option>
              </select>
            </div>

            <span className="text-slate-300 dark:text-slate-700">|</span>

            {/* Single Combined "Aa" Font-Size Dropdown */}
            <div className="flex items-center space-x-1">
              <span className="font-bold text-xs text-slate-500 select-none">Aa</span>
              <select
                value={fontSize}
                onChange={(e) => onFontSizeChange(e.target.value)}
                className="bg-transparent text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white text-xs font-medium focus:outline-none cursor-pointer py-0.5 border-0"
                aria-label="Adjust font size"
              >
                <option value="normal" className="bg-white text-slate-900 dark:bg-slate-900 dark:text-slate-100">Aa Normal</option>
                <option value="large" className="bg-white text-slate-900 dark:bg-slate-900 dark:text-slate-100">Aa Large</option>
                <option value="small" className="bg-white text-slate-900 dark:bg-slate-900 dark:text-slate-100">Aa Small</option>
              </select>
            </div>

            <span className="text-slate-300 dark:text-slate-700">|</span>

            {/* Dark Mode Toggle (Text-Only + Icon) */}
            <button
              type="button"
              onClick={onThemeToggle}
              className="flex items-center space-x-1 text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white text-xs font-medium transition-colors cursor-pointer"
              title={isDark ? "Switch to Light Theme" : "Switch to Dark Theme"}
              aria-label="Toggle theme"
            >
              {isDark ? <Sun className="w-3.5 h-3.5 text-slate-400" /> : <Moon className="w-3.5 h-3.5 text-slate-600" />}
              <span>{isDark ? (t.light || 'Light') : (t.dark || 'Dark')}</span>
            </button>

            <span className="text-slate-300 dark:text-slate-700">|</span>

            {/* Methodology Text Link */}
            <button
              type="button"
              onClick={onOpenMethodology}
              className="text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white text-xs font-medium hover:underline underline-offset-2 transition-colors cursor-pointer"
              title="View Technical Methodology & Security Audits"
            >
              <span>{t.methodology || 'Methodology'}</span>
            </button>

            <span className="text-slate-300 dark:text-slate-700">|</span>

            {/* Citizen Auth / My Checks Button */}
            {!currentUser ? (
              <button
                type="button"
                onClick={() => onOpenAuthModal('Please sign in or register to access the National Threat Triage Engine.')}
                className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full bg-cyan-700 hover:bg-cyan-800 text-white text-xs font-bold transition-all shadow-xs cursor-pointer select-none"
                title="Sign In or Register Citizen Account"
              >
                <LogIn className="w-3.5 h-3.5" />
                <span>Citizen Sign In</span>
              </button>
            ) : (
              <button
                type="button"
                onClick={() => onOpenAuthModal(null, 'history')}
                className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-slate-200/80 hover:bg-slate-300/80 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 text-xs font-semibold border border-slate-300 dark:border-slate-700 transition-all cursor-pointer select-none"
                title="Citizen Profile & My Checks"
              >
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                <span className="max-w-[110px] truncate">{currentUser.display_name?.split(' ')[0] || currentUser.email.split('@')[0]}</span>
                <span className="text-[10px] text-cyan-700 dark:text-cyan-400 font-bold bg-cyan-100/70 dark:bg-cyan-950/70 px-1.5 py-0.5 rounded border border-cyan-200 dark:border-cyan-800">
                  Checks
                </span>
              </button>
            )}
          </div>
        </div>
      </div>

      {/* ─── 4. Brand Row: Shield + Product Name + Tagline (Left), Single Expandable Status Pill (Right) ─── */}
      <div className="bg-white/80 dark:bg-[#0B0F19]/80 backdrop-blur-md border-b border-slate-200/80 dark:border-slate-800/80 text-slate-900 dark:text-white py-3.5 px-4 sm:px-6 transition-all relative z-30">
        <div className="max-w-7xl mx-auto flex items-center justify-between gap-4">
          {/* Left: Shield + Product Name + Tagline */}
          <div 
            className="group flex items-center space-x-3 cursor-pointer select-none" 
            onClick={() => onSelectFlow('home')}
            title="Go to Cyber Fraud Guardian Home"
          >
            <div className="w-9 h-9 rounded-xl bg-slate-900 text-white dark:bg-white dark:text-slate-950 flex items-center justify-center shadow-xs flex-shrink-0 group-hover:scale-105 transition-transform duration-200">
              <Shield className="w-5 h-5" strokeWidth={2.2} />
            </div>

            <div className="flex flex-col">
              <h1 className="text-base sm:text-lg font-bold tracking-tight text-slate-900 dark:text-white leading-tight">
                {t.portalTitle || 'Cyber Fraud Guardian'}
              </h1>
              <p className="text-xs text-slate-500 dark:text-slate-400 font-normal leading-tight">
                {t.portalTagline || 'National Citizen Cyber Threat Triage Portal'}
              </p>
            </div>
          </div>

          {/* Right: Single Expandable Status Pill (One element, not three!) */}
          <div className="relative" ref={statusRef}>
            <button
              type="button"
              onClick={() => setStatusExpanded(!statusExpanded)}
              className="inline-flex items-center space-x-2 px-3 py-1.5 rounded-full border border-slate-200 dark:border-slate-800 bg-slate-50/80 dark:bg-slate-900/60 text-slate-700 dark:text-slate-300 text-xs font-medium hover:border-slate-300 dark:hover:border-slate-700 transition-colors shadow-2xs cursor-pointer"
              aria-expanded={statusExpanded}
              aria-label="Toggle system status and privacy details"
            >
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </span>
              <span>{t.systemOperational || 'System Operational'}</span>
              <span className="hidden sm:inline text-slate-400 dark:text-slate-500 font-normal">
                ({activeModulesCount} Modules)
              </span>
              <ChevronDown className={`w-3.5 h-3.5 text-slate-400 transition-transform duration-200 ${statusExpanded ? 'rotate-180' : ''}`} />
            </button>

            {/* Expandable Dropdown Popover */}
            {statusExpanded && (
              <div 
                className="absolute right-0 mt-2 w-72 sm:w-80 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-xl p-4 z-40 text-xs space-y-3"
                role="region"
                aria-label="System Architecture Status"
              >
                <div className="flex items-center justify-between pb-2 border-b border-slate-100 dark:border-slate-800">
                  <span className="font-bold text-slate-900 dark:text-white">System Health & Controls</span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded-md bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400">
                    Track S2 • v0.1.0
                  </span>
                </div>

                <div className="space-y-2.5">
                  <div className="flex items-start space-x-2.5">
                    <span className="w-2 h-2 rounded-full bg-emerald-500 mt-1 flex-shrink-0" />
                    <div>
                      <strong className="text-slate-900 dark:text-white block font-medium">11 Modules Active</strong>
                      <p className="text-[11px] text-slate-500 dark:text-slate-400">Rule engine, Fast Laya, Safe Browsing, PhishTank, PhishStats & Epistemic Fusion ready.</p>
                    </div>
                  </div>

                  <div className="flex items-start space-x-2.5">
                    <span className="w-2 h-2 rounded-full bg-emerald-500 mt-1 flex-shrink-0" />
                    <div>
                      <strong className="text-slate-900 dark:text-white block font-medium">0-PII Retention Active</strong>
                      <p className="text-[11px] text-slate-500 dark:text-slate-400">Aadhaar, PAN & OTP numbers redacted in-memory prior to evaluation.</p>
                    </div>
                  </div>

                  <div className="flex items-start space-x-2.5">
                    <span className="w-2 h-2 rounded-full bg-emerald-500 mt-1 flex-shrink-0" />
                    <div>
                      <strong className="text-slate-900 dark:text-white block font-medium">Ephemeral Volatile Cache</strong>
                      <p className="text-[11px] text-slate-500 dark:text-slate-400">Bounded LRU memory cache; zero disk persistence of user submissions.</p>
                    </div>
                  </div>
                </div>

                <div className="pt-2.5 border-t border-slate-100 dark:border-slate-800 flex items-center justify-between text-[11px]">
                  <span className="text-slate-500 dark:text-slate-400">I4C Partner Initiative</span>
                  <a 
                    href="/verification.html" 
                    target="_blank" 
                    rel="noreferrer"
                    className="text-slate-900 dark:text-slate-200 font-semibold hover:underline inline-flex items-center space-x-1"
                  >
                    <span>Run Audits</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ─── 5. Nav Tabs: Clean Segmented Pill Navigation ─── */}
      <nav className="bg-white/60 dark:bg-[#0B0F19]/60 backdrop-blur-md border-b border-slate-200/60 dark:border-slate-800/60 px-4 sm:px-6 py-2" aria-label="Task Navigation">
        <div className="max-w-7xl mx-auto flex items-center space-x-1 overflow-x-auto text-xs scrollbar-none">
          <button
            type="button"
            onClick={() => onSelectFlow('home')}
            className={`px-3 py-1.5 rounded-lg text-xs transition-all duration-150 flex items-center space-x-1.5 whitespace-nowrap cursor-pointer ${
              currentFlow === 'home'
                ? 'bg-slate-900 text-white dark:bg-white dark:text-slate-900 font-semibold shadow-xs'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800/60 font-medium'
            }`}
          >
            <Home className="w-3.5 h-3.5" />
            <span>{t.navHome || 'Home'}</span>
          </button>

          <button
            type="button"
            onClick={() => {
              if (!currentUser) {
                onOpenAuthModal('Please sign in or register to access the Message Triage Scanner.');
                return;
              }
              onSelectFlow('message');
            }}
            className={`px-3 py-1.5 rounded-lg text-xs transition-all duration-150 flex items-center space-x-1.5 whitespace-nowrap cursor-pointer ${
              currentFlow === 'message'
                ? 'bg-slate-900 text-white dark:bg-white dark:text-slate-900 font-semibold shadow-xs'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800/60 font-medium'
            }`}
          >
            <MessageSquare className="w-3.5 h-3.5" />
            <span>{t.navMessage || 'Check Message / SMS'}</span>
            {!currentUser && <Lock className="w-2.5 h-2.5 opacity-50 ml-0.5" />}
          </button>

          <button
            type="button"
            onClick={() => {
              if (!currentUser) {
                onOpenAuthModal('Please sign in or register to access the URL Safety Inspector.');
                return;
              }
              onSelectFlow('url');
            }}
            className={`px-3 py-1.5 rounded-lg text-xs transition-all duration-150 flex items-center space-x-1.5 whitespace-nowrap cursor-pointer ${
              currentFlow === 'url'
                ? 'bg-slate-900 text-white dark:bg-white dark:text-slate-900 font-semibold shadow-xs'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800/60 font-medium'
            }`}
          >
            <Globe className="w-3.5 h-3.5" />
            <span>{t.navUrl || 'Check URL / Link'}</span>
            {!currentUser && <Lock className="w-2.5 h-2.5 opacity-50 ml-0.5" />}
          </button>

          <button
            type="button"
            onClick={() => {
              if (!currentUser) {
                onOpenAuthModal('Please sign in or register to access the Screenshot OCR Inspector.');
                return;
              }
              onSelectFlow('screenshot');
            }}
            className={`px-3.5 py-1.5 rounded-lg text-xs transition-all duration-150 flex items-center space-x-1.5 whitespace-nowrap cursor-pointer ${
              currentFlow === 'screenshot'
                ? 'bg-slate-900 text-white dark:bg-white dark:text-slate-900 font-semibold shadow-xs'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800/60 font-medium'
            }`}
          >
            <Camera className="w-3.5 h-3.5" />
            <span>{t.navScreenshot || 'Check Screenshot / Photo'}</span>
            {!currentUser && <Lock className="w-2.5 h-2.5 opacity-50 ml-0.5" />}
          </button>
        </div>
      </nav>
    </header>
  );
}
