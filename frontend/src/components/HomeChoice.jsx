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
    <div className="w-full max-w-4xl mx-auto space-y-8 py-6">
      {/* ─── Hero Heading & Subhead ─── */}
      <div className="text-center space-y-3">
        <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 text-slate-700 dark:text-slate-300 text-xs font-medium shadow-2xs">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
          <span>{t(lang, 'homeHeroBadge', 'National Citizen Cyber Threat Triage')}</span>
        </div>

        <h2 className="text-3xl sm:text-5xl font-extrabold tracking-tight text-slate-900 dark:text-white leading-tight">
          {t(lang, 'homeHeroTitle', 'What do you want to check?')}
        </h2>

        <p className="text-sm sm:text-base text-slate-600 dark:text-slate-400 max-w-2xl mx-auto font-normal leading-relaxed">
          {t(lang, 'homeHeroDesc', 'Cyber Fraud Guardian safely evaluates suspicious communications using passive forensic intelligence, protecting you without opening unsafe links or retaining your data.')}
        </p>
      </div>

      {/* ─── Access Gate Status Banner ─── */}
      {!currentUser ? (
        <div className="p-5 sm:p-6 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 flex flex-col md:flex-row items-center justify-between gap-5 shadow-xs">
          <div className="flex items-start space-x-4">
            <div className="w-11 h-11 rounded-xl bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 flex items-center justify-center flex-shrink-0">
              <Lock className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="px-2 py-0.5 rounded-md text-[10px] font-bold tracking-wide uppercase bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
                  Citizen Verification Required
                </span>
                <span className="text-[11px] text-slate-500 dark:text-slate-400">
                  Chain-of-Custody Protected
                </span>
              </div>
              <h3 className="text-sm sm:text-base font-bold text-slate-900 dark:text-white mt-1">
                Sign In to Access Forensic Cyber Threat Triage
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 leading-relaxed">
                In compliance with National Cyber Threat framework standards, users must log in to submit suspicious messages, analyze URLs, and access verified threat dossiers.
              </p>
            </div>
          </div>
          <div className="flex items-center space-x-2 flex-shrink-0 w-full md:w-auto">
            <button
              type="button"
              onClick={() => onOpenAuthModal('Please sign in or register to analyze suspicious communications.')}
              className="w-full md:w-auto px-5 py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 text-white dark:bg-white dark:hover:bg-slate-100 dark:text-slate-900 font-semibold text-xs transition-all shadow-xs flex items-center justify-center space-x-2 cursor-pointer"
            >
              <LogIn className="w-4 h-4" />
              <span>Sign In / Register</span>
            </button>
          </div>
        </div>
      ) : (
        <div className="p-4 rounded-xl bg-emerald-50/60 dark:bg-emerald-950/20 border border-emerald-200 dark:border-emerald-900/40 flex flex-col sm:flex-row items-center justify-between gap-3 shadow-2xs">
          <div className="flex items-center space-x-3">
            <div className="w-9 h-9 rounded-lg bg-emerald-600 text-white flex items-center justify-center flex-shrink-0 shadow-xs">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800 dark:bg-emerald-900/60 dark:text-emerald-300">
                  Verified Session
                </span>
                <span className="text-xs font-semibold text-slate-800 dark:text-slate-200">
                  {currentUser.display_name || currentUser.email}
                </span>
              </div>
              <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                Full forensic pipeline unlocked (Rules, ML, Laya, Brand, Safe Browsing, PhishTank, PhishStats, Neo4j Graph).
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={() => onOpenAuthModal(null, 'history')}
            className="px-3 py-1.5 rounded-lg border border-emerald-300 dark:border-emerald-800 bg-white dark:bg-slate-900 hover:bg-emerald-50 dark:hover:bg-emerald-950/60 text-xs font-medium text-emerald-800 dark:text-emerald-300 transition-colors flex items-center space-x-1.5 cursor-pointer shadow-2xs"
          >
            <History className="w-3.5 h-3.5" />
            <span>My Past Checks</span>
          </button>
        </div>
      )}

      {/* ─── 3 Primary Task Selection Cards ─── */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        {/* Choice 1: Message / SMS */}
        <button
          type="button"
          onClick={() => handleCardClick('message')}
          className="group text-left p-6 sm:p-7 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 shadow-xs hover:shadow-md transition-all duration-200 flex flex-col justify-between relative cursor-pointer"
        >
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="w-12 h-12 rounded-xl bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 flex items-center justify-center group-hover:bg-blue-600 group-hover:text-white transition-colors duration-200">
                <MessageSquare className="w-5 h-5" strokeWidth={2} />
              </div>
              {!currentUser && (
                <span className="inline-flex items-center space-x-1 text-[10px] font-medium px-2 py-0.5 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-700">
                  <Lock className="w-2.5 h-2.5" />
                  <span>Login</span>
                </span>
              )}
            </div>

            <div>
              <h3 className="text-base sm:text-lg font-bold text-slate-900 dark:text-white group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">
                {t(lang, 'choiceMessageTitle', 'Message / SMS')}
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1.5 leading-relaxed">
                {t(lang, 'choiceMessageDesc', 'Check suspicious text messages, WhatsApp forwards, bank alerts, electricity cutoff threats, or emails.')}
              </p>
            </div>
          </div>

          <div className="mt-6 pt-4 border-t border-slate-100 dark:border-slate-800 flex items-center justify-between text-xs font-semibold text-slate-700 dark:text-slate-300 group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">
            <span>{currentUser ? t(lang, 'choiceMessageAction', 'Analyze text message') : 'Sign in to analyze'}</span>
            <ArrowRight className="w-4 h-4 text-slate-400 group-hover:text-blue-600 dark:group-hover:text-blue-400 group-hover:translate-x-1 transition-all" />
          </div>
        </button>

        {/* Choice 2: URL / Website */}
        <button
          type="button"
          onClick={() => handleCardClick('url')}
          className="group text-left p-6 sm:p-7 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 shadow-xs hover:shadow-md transition-all duration-200 flex flex-col justify-between relative cursor-pointer"
        >
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="w-12 h-12 rounded-xl bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 flex items-center justify-center group-hover:bg-blue-600 group-hover:text-white transition-colors duration-200">
                <Globe className="w-5 h-5" strokeWidth={2} />
              </div>
              {!currentUser && (
                <span className="inline-flex items-center space-x-1 text-[10px] font-medium px-2 py-0.5 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-700">
                  <Lock className="w-2.5 h-2.5" />
                  <span>Login</span>
                </span>
              )}
            </div>

            <div>
              <h3 className="text-base sm:text-lg font-bold text-slate-900 dark:text-white group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">
                {t(lang, 'choiceUrlTitle', 'URL / Website')}
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1.5 leading-relaxed">
                {t(lang, 'choiceUrlDesc', 'Safely inspect a link or website without visiting it. Analyzes domain reputation, phishing feeds, and brand spoofing.')}
              </p>
            </div>
          </div>

          <div className="mt-6 pt-4 border-t border-slate-100 dark:border-slate-800 flex items-center justify-between text-xs font-semibold text-slate-700 dark:text-slate-300 group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">
            <span>{currentUser ? t(lang, 'choiceUrlAction', 'Inspect link safety') : 'Sign in to inspect'}</span>
            <ArrowRight className="w-4 h-4 text-slate-400 group-hover:text-blue-600 dark:group-hover:text-blue-400 group-hover:translate-x-1 transition-all" />
          </div>
        </button>

        {/* Choice 3: Screenshot / Photo */}
        <button
          type="button"
          onClick={() => handleCardClick('screenshot')}
          className="group text-left p-6 sm:p-7 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 shadow-xs hover:shadow-md transition-all duration-200 flex flex-col justify-between relative cursor-pointer"
        >
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="w-12 h-12 rounded-xl bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 flex items-center justify-center group-hover:bg-blue-600 group-hover:text-white transition-colors duration-200">
                <Camera className="w-5 h-5" strokeWidth={2} />
              </div>
              {!currentUser && (
                <span className="inline-flex items-center space-x-1 text-[10px] font-medium px-2 py-0.5 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-700">
                  <Lock className="w-2.5 h-2.5" />
                  <span>Login</span>
                </span>
              )}
            </div>

            <div>
              <h3 className="text-base sm:text-lg font-bold text-slate-900 dark:text-white group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">
                {t(lang, 'choiceScreenshotTitle', 'Screenshot / Photo')}
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1.5 leading-relaxed">
                {t(lang, 'choiceScreenshotDesc', 'Upload a screenshot or photo. Optical character recognition (OCR) extracts text and links for deep evaluation.')}
              </p>
            </div>
          </div>

          <div className="mt-6 pt-4 border-t border-slate-100 dark:border-slate-800 flex items-center justify-between text-xs font-semibold text-slate-700 dark:text-slate-300 group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">
            <span>{currentUser ? t(lang, 'choiceScreenshotAction', 'Upload screenshot') : 'Sign in to upload'}</span>
            <ArrowRight className="w-4 h-4 text-slate-400 group-hover:text-blue-600 dark:group-hover:text-blue-400 group-hover:translate-x-1 transition-all" />
          </div>
        </button>
      </div>

      {/* ─── Common Benchmark Typologies Quick-Test Bar ─── */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 space-y-3.5 shadow-xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
          <div className="flex items-center space-x-2 text-xs font-bold text-slate-800 dark:text-slate-200">
            <FlaskConical className="w-4 h-4 text-slate-500" />
            <span>{t(lang, 'presetsBarTitle', 'Or Quick-Test a Benchmark Scenario:')}</span>
            {!currentUser && (
              <span className="text-[10px] text-slate-400 font-normal">
                (Sign In Required)
              </span>
            )}
          </div>
          <span className="text-[11px] text-slate-500 dark:text-slate-400">
            {t(lang, 'presetsBarSub', 'Preloaded real-world fraud cases')}
          </span>
        </div>

        <div className="flex flex-wrap gap-2">
          {PRESET_SCENARIOS.map((preset) => (
            <button
              key={preset.id}
              type="button"
              onClick={() => handlePresetClick(preset)}
              className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/40 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 transition-colors cursor-pointer"
            >
              {!currentUser && <Lock className="w-2.5 h-2.5 text-slate-400" />}
              <span>{getPresetTitle(preset)}</span>
            </button>
          ))}
        </div>
      </div>

      {/* ─── Institutional Trust & Guarantee Badges ─── */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3.5 pt-2">
        <div className="flex items-center space-x-3 p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-xs text-slate-600 dark:text-slate-400 shadow-2xs">
          <div className="w-8 h-8 rounded-lg bg-slate-100 dark:bg-slate-800 flex items-center justify-center flex-shrink-0 text-slate-600 dark:text-slate-300">
            <Lock className="w-4 h-4" />
          </div>
          <span><strong>{t(lang, 'badgeZeroRetentionTitle', 'Zero Retention:')}</strong> {t(lang, 'badgeZeroRetentionDesc', 'Ephemeral in-memory analysis; zero storage.')}</span>
        </div>

        <div className="flex items-center space-x-3 p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-xs text-slate-600 dark:text-slate-400 shadow-2xs">
          <div className="w-8 h-8 rounded-lg bg-slate-100 dark:bg-slate-800 flex items-center justify-center flex-shrink-0 text-emerald-600 dark:text-emerald-400">
            <ShieldCheck className="w-4 h-4" />
          </div>
          <span><strong>{t(lang, 'badgeSafeSandboxTitle', 'Safe Sandbox:')}</strong> {t(lang, 'badgeSafeSandboxDesc', 'Unopened links tested via passive OSINT feeds.')}</span>
        </div>

        <div className="flex items-center space-x-3 p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-xs text-slate-600 dark:text-slate-400 shadow-2xs">
          <div className="w-8 h-8 rounded-lg bg-slate-100 dark:bg-slate-800 flex items-center justify-center flex-shrink-0 text-red-600 dark:text-red-400">
            <PhoneCall className="w-4 h-4" />
          </div>
          <span><strong>{t(lang, 'badge1930Title', '1930 Integration:')}</strong> {t(lang, 'badge1930Desc', 'Emergency Golden Hour guidance ready.')}</span>
        </div>
      </div>
    </div>
  );
}
