import React from 'react';
import { 
  MessageSquare, 
  Globe, 
  Camera, 
  ArrowRight, 
  ShieldCheck, 
  ShieldAlert,
  Lock, 
  PhoneCall, 
  FlaskConical, 
  LogIn,
  History,
  Sparkles,
  CheckCircle2
} from 'lucide-react';
import { PRESET_SCENARIOS } from '../data/presets';
import { t } from '../i18n/translations';

export default function HomeChoice({ 
  onSelectFlow, 
  onSelectPreset, 
  lang = 'en',
  currentUser = null,
  onOpenAuthModal = () => {}
}) {
  // Translate preset titles based on preset ID if present in dictionary
  const getPresetTitle = (preset) => {
    const key = `preset_${preset.id.replace(/-/g, '_')}`;
    return t(lang, key, preset.title);
  };

  const handleCardClick = (flowName) => {
    if (!currentUser) {
      onOpenAuthModal(`Please sign in or register as a citizen to access the ${flowName} triage engine.`);
      return;
    }
    onSelectFlow(flowName);
  };

  const handlePresetClick = (preset) => {
    if (!currentUser) {
      onOpenAuthModal('Please sign in or register to run benchmark forensic triage scenarios.');
      return;
    }
    onSelectPreset(preset);
  };

  return (
    <div className="w-full max-w-4xl mx-auto space-y-8 py-4">
      {/* ─── Hero Heading & Single-Sentence Purpose ─── */}
      <div className="text-center space-y-3">
        <div className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-800 dark:text-slate-200 text-xs font-semibold">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          <span>{t(lang, 'homeHeroBadge', 'National Citizen Cyber Threat Triage')}</span>
        </div>

        <h2 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-slate-900 dark:text-white">
          {t(lang, 'homeHeroTitle', 'What do you want to check?')}
        </h2>

        <p className="text-sm sm:text-base text-slate-600 dark:text-slate-400 max-w-2xl mx-auto leading-relaxed">
          {t(lang, 'homeHeroDesc', 'Cyber Fraud Guardian safely evaluates suspicious communications using passive forensic intelligence, protecting you without opening unsafe links or retaining your data.')}
        </p>
      </div>

      {/* ─── Access Gate Status Banner (Gating Notice vs Authenticated Citizen Banner) ─── */}
      {!currentUser ? (
        <div className="p-5 rounded-2xl bg-gradient-to-r from-amber-500/10 via-cyan-500/10 to-blue-500/10 border-2 border-cyan-600/30 dark:border-cyan-400/30 flex flex-col md:flex-row items-center justify-between gap-4 shadow-sm backdrop-blur-xs">
          <div className="flex items-start space-x-3.5">
            <div className="w-12 h-12 rounded-xl bg-cyan-700 dark:bg-cyan-600 text-white flex items-center justify-center flex-shrink-0 shadow-md">
              <Lock className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="px-2 py-0.5 rounded-full text-[10px] font-bold tracking-wide uppercase bg-cyan-100 text-cyan-800 dark:bg-cyan-950 dark:text-cyan-300 border border-cyan-300 dark:border-cyan-800">
                  Citizen Authentication Required
                </span>
                <span className="text-[11px] text-slate-500 dark:text-slate-400">
                  Chain-of-Custody Protected
                </span>
              </div>
              <h3 className="text-base font-bold text-slate-900 dark:text-white mt-1">
                Sign In to Access Forensic Cyber Threat Triage
              </h3>
              <p className="text-xs text-slate-600 dark:text-slate-400 mt-0.5 leading-relaxed">
                In compliance with National Cyber Threat framework standards, users must log in to submit suspicious messages, analyze URLs, and access verified threat dossiers.
              </p>
            </div>
          </div>
          <div className="flex items-center space-x-2 flex-shrink-0 w-full md:w-auto">
            <button
              type="button"
              onClick={() => onOpenAuthModal('Please sign in or register to analyze suspicious communications.')}
              className="w-full md:w-auto px-5 py-2.5 rounded-xl bg-cyan-700 hover:bg-cyan-800 active:bg-cyan-900 text-white font-bold text-xs shadow-md transition-all flex items-center justify-center space-x-2 cursor-pointer"
            >
              <LogIn className="w-4 h-4" />
              <span>Sign In / Register Citizen</span>
            </button>
          </div>
        </div>
      ) : (
        <div className="p-4 rounded-xl bg-emerald-50/80 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800 flex flex-col sm:flex-row items-center justify-between gap-3 shadow-xs">
          <div className="flex items-center space-x-3">
            <div className="w-9 h-9 rounded-lg bg-emerald-600 text-white flex items-center justify-center flex-shrink-0 shadow-xs">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800 dark:bg-emerald-900/60 dark:text-emerald-300">
                  Active Citizen Session
                </span>
                <span className="text-xs font-semibold text-slate-800 dark:text-slate-200">
                  {currentUser.display_name || currentUser.email}
                </span>
              </div>
              <p className="text-[11px] text-slate-600 dark:text-slate-400 mt-0.5">
                Full forensic pipeline unlocked (Rules, ML, Laya, Brand, Safe Browsing, PhishTank, PhishStats, Neo4j Graph).
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={() => onOpenAuthModal(null, 'history')}
            className="px-3.5 py-1.5 rounded-lg border border-emerald-300 dark:border-emerald-700 bg-white dark:bg-slate-900 hover:bg-emerald-50 dark:hover:bg-emerald-950/60 text-xs font-semibold text-emerald-800 dark:text-emerald-300 transition-colors flex items-center space-x-1.5 cursor-pointer shadow-2xs"
          >
            <History className="w-3.5 h-3.5" />
            <span>My Past Checks</span>
          </button>
        </div>
      )}

      {/* ─── 3 Primary Task Selection Cards ─── */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Choice 1: Message / SMS */}
        <button
          type="button"
          onClick={() => handleCardClick('message')}
          className={`group text-left p-6 bg-white dark:bg-slate-900 rounded-xl border transition-all duration-200 flex flex-col justify-between relative overflow-hidden ${
            !currentUser 
              ? 'border-slate-200 dark:border-slate-800 hover:border-cyan-500/70 dark:hover:border-cyan-500/70 cursor-pointer shadow-xs' 
              : 'border-slate-200 dark:border-slate-800 hover:border-slate-400 dark:hover:border-slate-600 hover:shadow-md cursor-pointer'
          }`}
        >
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div className="w-12 h-12 rounded-lg bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 flex items-center justify-center text-slate-800 dark:text-slate-200 group-hover:bg-slate-900 group-hover:text-white dark:group-hover:bg-slate-100 dark:group-hover:text-slate-900 transition-colors">
                <MessageSquare className="w-6 h-6" strokeWidth={1.8} />
              </div>
              {!currentUser && (
                <span className="inline-flex items-center space-x-1 text-[10px] font-bold px-2 py-0.5 rounded-full bg-amber-100 dark:bg-amber-950/60 text-amber-800 dark:text-amber-300 border border-amber-300 dark:border-amber-800">
                  <Lock className="w-2.5 h-2.5" />
                  <span>Login Required</span>
                </span>
              )}
            </div>

            <div>
              <h3 className="text-base font-bold text-slate-900 dark:text-white">
                {t(lang, 'choiceMessageTitle', 'Message / SMS')}
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 leading-relaxed">
                {t(lang, 'choiceMessageDesc', 'Check suspicious text messages, WhatsApp forwards, bank alerts, electricity cutoff threats, or emails.')}
              </p>
            </div>
          </div>

          <div className="mt-6 pt-4 border-t border-slate-100 dark:border-slate-800/80 flex items-center justify-between text-xs font-semibold text-slate-800 dark:text-slate-200">
            <span>{currentUser ? t(lang, 'choiceMessageAction', 'Analyze text message') : 'Sign in to analyze message'}</span>
            <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
          </div>
        </button>

        {/* Choice 2: URL / Website */}
        <button
          type="button"
          onClick={() => handleCardClick('url')}
          className={`group text-left p-6 bg-white dark:bg-slate-900 rounded-xl border transition-all duration-200 flex flex-col justify-between relative overflow-hidden ${
            !currentUser 
              ? 'border-slate-200 dark:border-slate-800 hover:border-cyan-500/70 dark:hover:border-cyan-500/70 cursor-pointer shadow-xs' 
              : 'border-slate-200 dark:border-slate-800 hover:border-slate-400 dark:hover:border-slate-600 hover:shadow-md cursor-pointer'
          }`}
        >
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div className="w-12 h-12 rounded-lg bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 flex items-center justify-center text-slate-800 dark:text-slate-200 group-hover:bg-slate-900 group-hover:text-white dark:group-hover:bg-slate-100 dark:group-hover:text-slate-900 transition-colors">
                <Globe className="w-6 h-6" strokeWidth={1.8} />
              </div>
              {!currentUser && (
                <span className="inline-flex items-center space-x-1 text-[10px] font-bold px-2 py-0.5 rounded-full bg-amber-100 dark:bg-amber-950/60 text-amber-800 dark:text-amber-300 border border-amber-300 dark:border-amber-800">
                  <Lock className="w-2.5 h-2.5" />
                  <span>Login Required</span>
                </span>
              )}
            </div>

            <div>
              <h3 className="text-base font-bold text-slate-900 dark:text-white">
                {t(lang, 'choiceUrlTitle', 'URL / Website')}
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 leading-relaxed">
                {t(lang, 'choiceUrlDesc', 'Safely inspect a link or website without visiting it. Analyzes domain reputation, phishing feeds, and brand spoofing.')}
              </p>
            </div>
          </div>

          <div className="mt-6 pt-4 border-t border-slate-100 dark:border-slate-800/80 flex items-center justify-between text-xs font-semibold text-slate-800 dark:text-slate-200">
            <span>{currentUser ? t(lang, 'choiceUrlAction', 'Inspect link safety') : 'Sign in to inspect link'}</span>
            <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
          </div>
        </button>

        {/* Choice 3: Screenshot / Photo */}
        <button
          type="button"
          onClick={() => handleCardClick('screenshot')}
          className={`group text-left p-6 bg-white dark:bg-slate-900 rounded-xl border transition-all duration-200 flex flex-col justify-between relative overflow-hidden ${
            !currentUser 
              ? 'border-slate-200 dark:border-slate-800 hover:border-cyan-500/70 dark:hover:border-cyan-500/70 cursor-pointer shadow-xs' 
              : 'border-slate-200 dark:border-slate-800 hover:border-slate-400 dark:hover:border-slate-600 hover:shadow-md cursor-pointer'
          }`}
        >
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div className="w-12 h-12 rounded-lg bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 flex items-center justify-center text-slate-800 dark:text-slate-200 group-hover:bg-slate-900 group-hover:text-white dark:group-hover:bg-slate-100 dark:group-hover:text-slate-900 transition-colors">
                <Camera className="w-6 h-6" strokeWidth={1.8} />
              </div>
              {!currentUser && (
                <span className="inline-flex items-center space-x-1 text-[10px] font-bold px-2 py-0.5 rounded-full bg-amber-100 dark:bg-amber-950/60 text-amber-800 dark:text-amber-300 border border-amber-300 dark:border-amber-800">
                  <Lock className="w-2.5 h-2.5" />
                  <span>Login Required</span>
                </span>
              )}
            </div>

            <div>
              <h3 className="text-base font-bold text-slate-900 dark:text-white">
                {t(lang, 'choiceScreenshotTitle', 'Screenshot / Photo')}
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 leading-relaxed">
                {t(lang, 'choiceScreenshotDesc', 'Upload a screenshot or photo. Optical character recognition (OCR) extracts text and links for deep evaluation.')}
              </p>
            </div>
          </div>

          <div className="mt-6 pt-4 border-t border-slate-100 dark:border-slate-800/80 flex items-center justify-between text-xs font-semibold text-slate-800 dark:text-slate-200">
            <span>{currentUser ? t(lang, 'choiceScreenshotAction', 'Upload screenshot') : 'Sign in to upload photo'}</span>
            <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
          </div>
        </button>
      </div>

      {/* ─── Common Benchmark Typologies Quick-Test Bar ─── */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
          <div className="flex items-center space-x-1.5 text-xs font-bold text-slate-800 dark:text-slate-200">
            <FlaskConical className="w-3.5 h-3.5 text-slate-600 dark:text-slate-400" />
            <span>{t(lang, 'presetsBarTitle', 'Or Quick-Test a Benchmark Scenario:')}</span>
            {!currentUser && (
              <span className="ml-1 text-[10px] text-amber-600 dark:text-amber-400 font-normal">
                (Sign In Required)
              </span>
            )}
          </div>
          <span className="text-[11px] text-slate-500 dark:text-slate-400">
            {t(lang, 'presetsBarSub', 'Preloaded real-world fraud cases')}
          </span>
        </div>

        <div className="flex flex-wrap gap-1.5">
          {PRESET_SCENARIOS.map((preset) => (
            <button
              key={preset.id}
              type="button"
              onClick={() => handlePresetClick(preset)}
              className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-md text-xs font-medium border border-slate-300 dark:border-slate-700 bg-slate-50 hover:bg-slate-100 dark:bg-slate-800/80 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-200 transition-colors cursor-pointer"
            >
              {!currentUser && <Lock className="w-2.5 h-2.5 text-slate-400" />}
              <span>{getPresetTitle(preset)}</span>
            </button>
          ))}
        </div>
      </div>

      {/* ─── Institutional Trust & Guarantee Badges ─── */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2">
        <div className="flex items-center space-x-2.5 p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-white/60 dark:bg-slate-900/60 text-xs text-slate-600 dark:text-slate-400">
          <Lock className="w-4 h-4 text-slate-500 dark:text-slate-400 flex-shrink-0" />
          <span><strong>{t(lang, 'badgeZeroRetentionTitle', 'Zero Retention:')}</strong> {t(lang, 'badgeZeroRetentionDesc', 'Ephemeral in-memory analysis; zero storage.')}</span>
        </div>

        <div className="flex items-center space-x-2.5 p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-white/60 dark:bg-slate-900/60 text-xs text-slate-600 dark:text-slate-400">
          <ShieldCheck className="w-4 h-4 text-emerald-600 dark:text-emerald-500 flex-shrink-0" />
          <span><strong>{t(lang, 'badgeSafeSandboxTitle', 'Safe Sandbox:')}</strong> {t(lang, 'badgeSafeSandboxDesc', 'Unopened links tested via passive OSINT feeds.')}</span>
        </div>

        <div className="flex items-center space-x-2.5 p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-white/60 dark:bg-slate-900/60 text-xs text-slate-600 dark:text-slate-400">
          <PhoneCall className="w-4 h-4 text-red-600 dark:text-red-500 flex-shrink-0" />
          <span><strong>{t(lang, 'badge1930Title', '1930 Integration:')}</strong> {t(lang, 'badge1930Desc', 'Emergency Golden Hour guidance ready.')}</span>
        </div>
      </div>
    </div>
  );
}
