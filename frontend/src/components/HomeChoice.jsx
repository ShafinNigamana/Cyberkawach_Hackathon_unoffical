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
  CheckCircle2,
  Cpu,
  Layers,
  Zap,
  Activity,
  ScanText
} from 'lucide-react';
import { PRESET_SCENARIOS } from '../data/presets';
import { t } from '../i18n/translations';

export default function HomeChoice({ 
  onSelectFlow, 
  onSelectPreset, 
  lang = 'en',
  currentUser = null,
  onOpenAuthModal = () => {},
  healthData = null
}) {
  const totalModulesCount = healthData?.modules 
    ? Object.keys(healthData.modules).length 
    : 12;

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
    <div className="w-full max-w-5xl mx-auto space-y-8 py-4 sm:py-6">
      {/* ─── Hero Section ─── */}
      <div className="relative space-y-4 pt-4 pb-2 text-left sm:text-center">
        {/* Status Badge */}
        <div className="inline-flex items-center space-x-2 px-3 py-1.5 rounded-full border border-slate-200 dark:border-border-dark bg-white dark:bg-surface-dark-elevated text-slate-700 dark:text-slate-300 text-xs font-semibold">
          <span className="w-2 h-2 rounded-full bg-emerald-500" />
          <span>{t(lang, 'homeHeroBadge', 'National Citizen Cyber Threat Triage')}</span>
        </div>

        {/* Main Headline */}
        <h2 className="text-3xl sm:text-4xl lg:text-5xl font-black tracking-tight text-slate-900 dark:text-white leading-[1.15]">
          Verify threats before{' '}
          <span className="text-accent dark:text-emerald-400">
            you click or pay
          </span>
        </h2>

        {/* Supporting description */}
        <p className="text-sm sm:text-base text-slate-600 dark:text-slate-300 max-w-2xl mx-auto font-normal leading-relaxed">
          {t(lang, 'homeHeroDesc', 'Cyber Fraud Guardian safely evaluates suspicious communications using passive forensic intelligence, protecting you without opening unsafe links or retaining your data.')}
        </p>

        {/* Quick Executive Telemetry Strip */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 max-w-3xl mx-auto pt-2">
          <div className="p-2.5 rounded-xl border border-slate-200/80 dark:border-border-dark bg-white/70 dark:bg-surface-dark-elevated/70 backdrop-blur-sm text-left">
            <div className="flex items-center space-x-1.5 text-slate-500 dark:text-slate-400 text-[10px] font-bold uppercase tracking-wider">
              <Cpu className="w-3 h-3 text-accent" />
              <span>Pipeline</span>
            </div>
            <div className="text-sm font-extrabold text-slate-900 dark:text-white mt-0.5">
              {totalModulesCount} Modules
            </div>
          </div>

          <div className="p-2.5 rounded-xl border border-slate-200/80 dark:border-border-dark bg-white/70 dark:bg-surface-dark-elevated/70 backdrop-blur-sm text-left">
            <div className="flex items-center space-x-1.5 text-slate-500 dark:text-slate-400 text-[10px] font-bold uppercase tracking-wider">
              <Lock className="w-3 h-3 text-emerald-500" />
              <span>Privacy</span>
            </div>
            <div className="text-sm font-extrabold text-slate-900 dark:text-white mt-0.5">
              0-PII In-Memory
            </div>
          </div>

          <div className="p-2.5 rounded-xl border border-slate-200/80 dark:border-border-dark bg-white/70 dark:bg-surface-dark-elevated/70 backdrop-blur-sm text-left">
            <div className="flex items-center space-x-1.5 text-slate-500 dark:text-slate-400 text-[10px] font-bold uppercase tracking-wider">
              <PhoneCall className="w-3 h-3 text-rose-500" />
              <span>Emergency</span>
            </div>
            <div className="text-sm font-extrabold text-slate-900 dark:text-white mt-0.5">
              1930 Protocol
            </div>
          </div>

          <div className="p-2.5 rounded-xl border border-slate-200/80 dark:border-border-dark bg-white/70 dark:bg-surface-dark-elevated/70 backdrop-blur-sm text-left">
            <div className="flex items-center space-x-1.5 text-slate-500 dark:text-slate-400 text-[10px] font-bold uppercase tracking-wider">
              <ScanText className="w-3 h-3 text-amber-500" />
              <span>Multi-modal</span>
            </div>
            <div className="text-sm font-extrabold text-slate-900 dark:text-white mt-0.5">
              OCR & Voice
            </div>
          </div>
        </div>
      </div>

      {/* ─── Citizen Access Gate Status Banner ─── */}
      {!currentUser ? (
        <div className="clean-card clean-card-hover p-5 sm:p-6 flex flex-col md:flex-row items-center justify-between gap-5">
          <div className="flex items-start space-x-4">
            <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-accent/20 to-accent-hover/20 text-accent dark:text-emerald-400 flex items-center justify-center flex-shrink-0 border border-emerald-500/20">
              <Lock className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold tracking-wide uppercase bg-emerald-50 text-emerald-700 dark:bg-emerald-950/80 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800">
                  Citizen Verification Required
                </span>
                <span className="text-[11px] text-slate-500 dark:text-slate-400 font-medium">
                  Chain-of-Custody Protected
                </span>
              </div>
              <h3 className="text-sm sm:text-base font-bold text-slate-900 dark:text-white mt-1">
                Authenticate to Access Verified Threat Triage
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 leading-relaxed">
                In compliance with National Cyber Threat framework standards, users sign in to submit suspicious messages, inspect URLs, and receive forensic reports.
              </p>
            </div>
          </div>
          <div className="flex items-center space-x-2 flex-shrink-0 w-full md:w-auto">
            <button
              type="button"
              onClick={() => onOpenAuthModal('Please sign in or register to analyze suspicious communications.')}
              className="w-full md:w-auto px-6 py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 dark:bg-accent dark:hover:bg-accent-hover text-white font-bold text-xs transition-all shadow-card flex items-center justify-center space-x-2 cursor-pointer active:scale-[0.98]"
            >
              <LogIn className="w-4 h-4" />
              <span>Sign In / Register</span>
            </button>
          </div>
        </div>
      ) : (
        <div className="p-4 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 flex flex-col sm:flex-row items-center justify-between gap-3 shadow-2xs">
          <div className="flex items-center space-x-3.5">
            <div className="w-10 h-10 rounded-xl bg-emerald-600 text-white flex items-center justify-center flex-shrink-0 shadow-sm">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-700 dark:text-emerald-300">
                  Verified Session
                </span>
                <span className="text-xs font-bold text-slate-900 dark:text-white">
                  {currentUser.display_name || currentUser.email}
                </span>
              </div>
              <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                Full forensic pipeline unlocked (Rules, ML, Laya, Brand, Safe Browsing, PhishTank, PhishStats).
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={() => onOpenAuthModal(null, 'history')}
            className="px-3.5 py-2 rounded-xl border border-emerald-400/40 bg-white dark:bg-surface-dark-elevated hover:bg-emerald-50 dark:hover:bg-emerald-950/40 text-xs font-bold text-emerald-800 dark:text-emerald-300 transition-colors flex items-center space-x-1.5 cursor-pointer shadow-2xs"
          >
            <History className="w-3.5 h-3.5" />
            <span>My Past Checks</span>
          </button>
        </div>
      )}

      {/* ─── 3 Primary Interactive Launchpad Cards ─── */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        {/* Card 1: Message / SMS */}
        <button
          type="button"
          onClick={() => handleCardClick('message')}
          className="clean-card clean-card-hover text-left p-6 sm:p-7 flex flex-col justify-between group cursor-pointer"
        >
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="w-12 h-12 rounded-2xl bg-emerald-500/10 text-accent dark:bg-emerald-500/12 dark:text-emerald-400 flex items-center justify-center group-hover:scale-110 transition-transform duration-200">
                <MessageSquare className="w-6 h-6" strokeWidth={2} />
              </div>
              {!currentUser && (
                <span className="inline-flex items-center space-x-1 text-[10px] font-bold px-2 py-0.5 rounded-full bg-slate-100 dark:bg-surface-dark-hover text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-border-dark">
                  <Lock className="w-2.5 h-2.5" />
                  <span>Login</span>
                </span>
              )}
            </div>

            <div>
              <h3 className="text-base sm:text-lg font-bold text-slate-900 dark:text-white group-hover:text-accent dark:group-hover:text-emerald-400 transition-colors">
                {t(lang, 'choiceMessageTitle', 'Message / SMS')}
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-2 leading-relaxed">
                {t(lang, 'choiceMessageDesc', 'Check suspicious text messages, WhatsApp forwards, bank alerts, electricity cutoff threats, or emails.')}
              </p>
            </div>

            <div className="space-y-1.5 pt-2 text-[11px] text-slate-600 dark:text-slate-400">
              <div className="flex items-center space-x-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-accent" />
                <span>Voice mic input supported</span>
              </div>
              <div className="flex items-center space-x-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-accent" />
                <span>Urgency tactics & bank scams</span>
              </div>
            </div>
          </div>

          <div className="mt-6 pt-4 border-t border-slate-100 dark:border-border-dark flex items-center justify-between text-xs font-bold text-slate-800 dark:text-slate-200 group-hover:text-accent dark:group-hover:text-emerald-400 transition-colors">
            <span>{currentUser ? t(lang, 'choiceMessageAction', 'Analyze text message') : 'Sign in to analyze'}</span>
            <ArrowRight className="w-4 h-4 text-slate-400 group-hover:text-accent dark:group-hover:text-emerald-400 group-hover:translate-x-1 transition-all" />
          </div>
        </button>

        {/* Card 2: URL / Website */}
        <button
          type="button"
          onClick={() => handleCardClick('url')}
          className="clean-card clean-card-hover text-left p-6 sm:p-7 flex flex-col justify-between group cursor-pointer"
        >
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="w-12 h-12 rounded-2xl bg-cyan-500/10 text-cyan-600 dark:bg-cyan-500/15 dark:text-cyan-400 flex items-center justify-center group-hover:scale-110 transition-transform duration-200">
                <Globe className="w-6 h-6" strokeWidth={2} />
              </div>
              {!currentUser && (
                <span className="inline-flex items-center space-x-1 text-[10px] font-bold px-2 py-0.5 rounded-full bg-slate-100 dark:bg-surface-dark-hover text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-border-dark">
                  <Lock className="w-2.5 h-2.5" />
                  <span>Login</span>
                </span>
              )}
            </div>

            <div>
              <h3 className="text-base sm:text-lg font-bold text-slate-900 dark:text-white group-hover:text-cyan-600 dark:group-hover:text-cyan-400 transition-colors">
                {t(lang, 'choiceUrlTitle', 'URL / Website')}
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-2 leading-relaxed">
                {t(lang, 'choiceUrlDesc', 'Safely inspect a link or website without visiting it. Analyzes domain reputation, phishing feeds, and brand spoofing.')}
              </p>
            </div>

            <div className="space-y-1.5 pt-2 text-[11px] text-slate-600 dark:text-slate-400">
              <div className="flex items-center space-x-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-cyan-500" />
                <span>Zero outbound visits (Safe sandbox)</span>
              </div>
              <div className="flex items-center space-x-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-cyan-500" />
                <span>Safe Browsing & PhishTank feeds</span>
              </div>
            </div>
          </div>

          <div className="mt-6 pt-4 border-t border-slate-100 dark:border-border-dark flex items-center justify-between text-xs font-bold text-slate-800 dark:text-slate-200 group-hover:text-cyan-600 dark:group-hover:text-cyan-400 transition-colors">
            <span>{currentUser ? t(lang, 'choiceUrlAction', 'Inspect link safety') : 'Sign in to inspect'}</span>
            <ArrowRight className="w-4 h-4 text-slate-400 group-hover:text-cyan-600 dark:group-hover:text-cyan-400 group-hover:translate-x-1 transition-all" />
          </div>
        </button>

        {/* Card 3: Screenshot / Photo */}
        <button
          type="button"
          onClick={() => handleCardClick('screenshot')}
          className="clean-card clean-card-hover text-left p-6 sm:p-7 flex flex-col justify-between group cursor-pointer"
        >
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="w-12 h-12 rounded-2xl bg-amber-500/10 text-amber-600 dark:bg-amber-500/12 dark:text-amber-400 flex items-center justify-center group-hover:scale-110 transition-transform duration-200">
                <Camera className="w-6 h-6" strokeWidth={2} />
              </div>
              {!currentUser && (
                <span className="inline-flex items-center space-x-1 text-[10px] font-bold px-2 py-0.5 rounded-full bg-slate-100 dark:bg-surface-dark-hover text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-border-dark">
                  <Lock className="w-2.5 h-2.5" />
                  <span>Login</span>
                </span>
              )}
            </div>

            <div>
              <h3 className="text-base sm:text-lg font-bold text-slate-900 dark:text-white group-hover:text-amber-600 dark:group-hover:text-amber-400 transition-colors">
                {t(lang, 'choiceScreenshotTitle', 'Screenshot / Photo')}
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-2 leading-relaxed">
                {t(lang, 'choiceScreenshotDesc', 'Upload a screenshot or photo. Optical character recognition (OCR) extracts text and links for deep evaluation.')}
              </p>
            </div>

            <div className="space-y-1.5 pt-2 text-[11px] text-slate-600 dark:text-slate-400">
              <div className="flex items-center space-x-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-amber-500" />
                <span>Instant automated OCR extraction</span>
              </div>
              <div className="flex items-center space-x-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-amber-500" />
                <span>Extracts embedded scam links</span>
              </div>
            </div>
          </div>

          <div className="mt-6 pt-4 border-t border-slate-100 dark:border-border-dark flex items-center justify-between text-xs font-bold text-slate-800 dark:text-slate-200 group-hover:text-amber-600 dark:group-hover:text-amber-400 transition-colors">
            <span>{currentUser ? t(lang, 'choiceScreenshotAction', 'Upload screenshot') : 'Sign in to upload'}</span>
            <ArrowRight className="w-4 h-4 text-slate-400 group-hover:text-amber-600 dark:group-hover:text-amber-400 group-hover:translate-x-1 transition-all" />
          </div>
        </button>
      </div>

      {/* ─── Benchmark Typologies Quick-Test Section ─── */}
      <div className="clean-card clean-card-hover p-5 sm:p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
          <div className="flex items-center space-x-2 text-xs font-bold text-slate-900 dark:text-white">
            <FlaskConical className="w-4 h-4 text-accent dark:text-emerald-400" />
            <span>{t(lang, 'presetsBarTitle', 'Preloaded Benchmark Threat Scenarios:')}</span>
            {!currentUser && (
              <span className="text-[10px] text-slate-400 font-normal">
                (Sign In Required)
              </span>
            )}
          </div>
          <span className="text-[11px] text-slate-500 dark:text-slate-400">
            {t(lang, 'presetsBarSub', 'Real-world Indian cybercrime typologies')}
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
          {PRESET_SCENARIOS.map((preset) => (
            <button
              key={preset.id}
              type="button"
              onClick={() => handlePresetClick(preset)}
              className="p-3 rounded-xl border border-slate-200/90 dark:border-border-dark bg-slate-50/70 dark:bg-surface-dark-hover/60 hover:bg-white dark:hover:bg-surface-dark-hover hover:border-emerald-500/30 text-left transition-all group cursor-pointer shadow-2xs"
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-bold text-slate-800 dark:text-slate-200 group-hover:text-accent dark:group-hover:text-emerald-300 transition-colors truncate">
                  {getPresetTitle(preset)}
                </span>
                {!currentUser && <Lock className="w-3 h-3 text-slate-400 ml-1 flex-shrink-0" />}
              </div>
              <p className="text-[11px] text-slate-500 dark:text-slate-400 line-clamp-1">
                {preset.message}
              </p>
            </button>
          ))}
        </div>
      </div>

      {/* ─── Institutional Trust & Guarantee Badges ─── */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3.5 pt-2">
        <div className="flex items-center space-x-3.5 p-4 rounded-xl border border-slate-200/80 dark:border-border-dark bg-white dark:bg-surface-dark-elevated text-xs text-slate-600 dark:text-slate-400 shadow-2xs">
          <div className="w-9 h-9 rounded-xl bg-emerald-50 dark:bg-surface-dark-hover flex items-center justify-center flex-shrink-0 text-accent dark:text-emerald-400">
            <Lock className="w-4.5 h-4.5" />
          </div>
          <div>
            <strong className="text-slate-900 dark:text-white block font-bold">
              {t(lang, 'badgeZeroRetentionTitle', 'Zero Retention')}
            </strong>
            <span className="text-[11px]">{t(lang, 'badgeZeroRetentionDesc', 'Ephemeral in-memory analysis; zero storage.')}</span>
          </div>
        </div>

        <div className="flex items-center space-x-3.5 p-4 rounded-xl border border-slate-200/80 dark:border-border-dark bg-white dark:bg-surface-dark-elevated text-xs text-slate-600 dark:text-slate-400 shadow-2xs">
          <div className="w-9 h-9 rounded-xl bg-emerald-50 dark:bg-surface-dark-hover flex items-center justify-center flex-shrink-0 text-emerald-600 dark:text-emerald-400">
            <ShieldCheck className="w-4.5 h-4.5" />
          </div>
          <div>
            <strong className="text-slate-900 dark:text-white block font-bold">
              {t(lang, 'badgeSafeSandboxTitle', 'Safe Sandbox')}
            </strong>
            <span className="text-[11px]">{t(lang, 'badgeSafeSandboxDesc', 'Unopened links tested via passive OSINT feeds.')}</span>
          </div>
        </div>

        <div className="flex items-center space-x-3.5 p-4 rounded-xl border border-slate-200/80 dark:border-border-dark bg-white dark:bg-surface-dark-elevated text-xs text-slate-600 dark:text-slate-400 shadow-2xs">
          <div className="w-9 h-9 rounded-xl bg-rose-50 dark:bg-surface-dark-hover flex items-center justify-center flex-shrink-0 text-rose-600 dark:text-rose-400">
            <PhoneCall className="w-4.5 h-4.5" />
          </div>
          <div>
            <strong className="text-slate-900 dark:text-white block font-bold">
              {t(lang, 'badge1930Title', '1930 Integration')}
            </strong>
            <span className="text-[11px]">{t(lang, 'badge1930Desc', 'Emergency Golden Hour guidance ready.')}</span>
          </div>
        </div>
      </div>
    </div>
  );
}
