import React, { useState } from 'react';
import { 
  ArrowLeft, 
  Globe, 
  ShieldCheck, 
  ShieldAlert, 
  ClipboardPaste, 
  Eraser, 
  Search, 
  Loader2, 
  AlertCircle, 
  ExternalLink,
  Lock,
  Layers,
  CheckCircle2
} from 'lucide-react';
import { t } from '../i18n/translations';

const URL_PRESETS = [
  { id: 'sbi-phish', label: 'SBI KYC Phish', url: 'http://sbi-kyc-verify-urgent.com/login', type: 'phish' },
  { id: 'power-phish', label: 'Electricity Cutoff Portal', url: 'http://power-bill-payment.top', type: 'phish' },
  { id: 'post-phish', label: 'India Post Fee Scam', url: 'http://india-post-consignment.live', type: 'phish' },
  { id: 'sbi-safe', label: 'Official Bank (Safe Control)', url: 'https://onlinesbi.sbi', type: 'safe' },
];

export default function FlowUrl({ onBack, onSubmit, isAnalyzing, initialUrl = '', lang = 'en' }) {
  const [url, setUrl] = useState(initialUrl);
  const [userState, setUserState] = useState('received');
  const [validationError, setValidationError] = useState(null);

  const handlePaste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        setUrl(text.trim());
        setValidationError(null);
      }
    } catch {
      // Fallback
    }
  };

  const handleClear = () => {
    setUrl('');
    setValidationError(null);
  };

  const handleFormSubmit = (e) => {
    if (e) e.preventDefault();
    if (!url || !url.trim()) {
      setValidationError(t(lang, 'urlPlaceholder', 'Please enter or paste a URL / website link to analyze.'));
      return;
    }

    const trimmed = url.trim();
    if (!trimmed.includes('.') || trimmed.length < 4) {
      setValidationError(t(lang, 'urlPlaceholder', 'Please enter a valid web address or domain (e.g., sbi-kyc-login.com).'));
      return;
    }

    setValidationError(null);
    onSubmit({
      message: `Forensic Link Inspection for: ${trimmed}`,
      urls: [trimmed],
      input_type: 'url',
      user_state: userState,
    });
  };

  return (
    <div className="w-full max-w-3xl mx-auto space-y-5">
      {/* ─── Breadcrumb & Navigation Header ─── */}
      <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-3">
        <button
          type="button"
          onClick={onBack}
          className="inline-flex items-center space-x-1.5 text-xs font-semibold text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white transition-colors cursor-pointer"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>{t(lang, 'backToSelection', 'Back to Task Selection')}</span>
        </button>

        <span className="text-xs font-mono font-medium text-slate-500 dark:text-slate-400">
          {t(lang, 'flowUrlBreadcrumb', 'Flow: Check URL / Website')}
        </span>
      </div>

      {/* ─── Flow Title & Safe Sandbox Notice ─── */}
      <div className="space-y-1">
        <div className="flex items-center space-x-2">
          <div className="w-8 h-8 rounded-lg bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900 flex items-center justify-center flex-shrink-0">
            <Globe className="w-4 h-4" />
          </div>
          <h2 className="text-xl font-extrabold text-slate-900 dark:text-white">
            {t(lang, 'flowUrlTitle', 'Inspect Suspicious URL or Website')}
          </h2>
        </div>
        <p className="text-xs text-slate-600 dark:text-slate-400 pl-10">
          {t(lang, 'flowUrlDesc', 'Analyze suspicious domains, shortened links, or fraudulent payment portals.')}
        </p>
      </div>

      {/* ─── Safety Guarantee Banner ─── */}
      <div className="luxury-card p-4 flex items-start space-x-3.5 border-emerald-500/20 bg-emerald-500/5">
        <ShieldCheck className="w-5 h-5 text-emerald-500 flex-shrink-0 mt-0.5" />
        <div className="text-xs space-y-1">
          <h4 className="font-bold text-slate-900 dark:text-white">
            {t(lang, 'sandboxGuarantee', 'Safe Sandbox Isolation Guarantee')}
          </h4>
          <p className="text-slate-600 dark:text-slate-400 leading-relaxed">
            {t(lang, 'sandboxGuaranteeText', 'This URL will be queried strictly using passive threat intelligence (Google Safe Browsing, PhishTank, PhishStats), domain structure entropy, and official brand impersonation matching. It is NEVER opened in your local browser or connected to your device.')}
          </p>
        </div>
      </div>

      {/* ─── Example URL Shortcuts ─── */}
      <div className="space-y-2">
        <span className="text-xs font-bold text-slate-700 dark:text-slate-300">
          {t(lang, 'selectSampleLink', 'Or Select a Sample Link to Test:')}
        </span>
        <div className="flex flex-wrap gap-2">
          {URL_PRESETS.map((preset) => (
            <button
              key={preset.id}
              type="button"
              onClick={() => {
                setUrl(preset.url);
                setValidationError(null);
              }}
              className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold border border-slate-200 dark:border-night-border bg-white dark:bg-night-850 hover:bg-slate-50 dark:hover:bg-night-800 text-slate-800 dark:text-slate-200 transition-colors cursor-pointer shadow-2xs"
            >
              <span className={`w-2 h-2 rounded-full ${preset.type === 'safe' ? 'bg-emerald-500' : 'bg-rose-500'}`} />
              <span>{preset.label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* ─── Focused URL Analysis Form ─── */}
      <form onSubmit={handleFormSubmit} noValidate className="luxury-card p-6 space-y-5 shadow-sm">
        <div>
          <div className="flex items-center justify-between mb-2">
            <label htmlFor="flow-url-input" className="text-xs font-bold text-slate-900 dark:text-slate-100">
              {t(lang, 'targetUrlLabel', 'Target Website URL or Domain')} <span className="text-rose-500 font-bold">*</span>
            </label>
            <div className="flex items-center space-x-2">
              <button
                type="button"
                onClick={handlePaste}
                className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-slate-200 dark:bg-night-800 dark:hover:bg-night-750 text-slate-700 dark:text-slate-300 text-xs font-semibold transition-colors cursor-pointer border border-slate-200 dark:border-night-border"
                title="Paste from clipboard"
              >
                <ClipboardPaste className="w-3.5 h-3.5 text-cyan-500" />
                <span>{t(lang, 'paste', 'Paste')}</span>
              </button>
              <button
                type="button"
                onClick={handleClear}
                className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-slate-200 dark:bg-night-800 dark:hover:bg-night-750 text-slate-700 dark:text-slate-300 text-xs font-semibold transition-colors cursor-pointer border border-slate-200 dark:border-night-border"
                title="Clear input"
              >
                <Eraser className="w-3.5 h-3.5 text-slate-400" />
                <span>{t(lang, 'clear', 'Clear')}</span>
              </button>
            </div>
          </div>

          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
              <Globe className="w-4 h-4 text-cyan-500" />
            </div>
            <input
              type="text"
              id="flow-url-input"
              value={url}
              onChange={(e) => {
                setUrl(e.target.value);
                if (validationError) setValidationError(null);
              }}
              placeholder={t(lang, 'urlPlaceholder', 'e.g. sbi-kyc-verify-urgent.com or http://power-bill-payment.top')}
              className={`w-full bg-slate-50/80 text-slate-900 placeholder-slate-400 border rounded-2xl pl-10 pr-3 py-3 text-xs sm:text-sm font-mono focus:outline-none focus:ring-2 focus:ring-cyan-500/30 focus:border-cyan-500 dark:bg-night-950/80 dark:text-slate-100 dark:placeholder-slate-500 transition-all ${
                validationError ? 'border-rose-500 ring-1 ring-rose-500' : 'border-slate-200 dark:border-night-border'
              }`}
            />
          </div>

          {validationError && (
            <p className="mt-2 text-xs text-rose-600 dark:text-rose-400 font-semibold flex items-center space-x-1">
              <AlertCircle className="w-3.5 h-3.5 inline mr-1 flex-shrink-0" />
              <span>{validationError}</span>
            </p>
          )}
        </div>

        {/* Citizen Situation State */}
        <div>
          <label htmlFor="url-user-state" className="block text-xs font-bold text-slate-900 dark:text-slate-200 mb-1.5">
            {t(lang, 'interactQuestion', 'Did you interact with this link?')} <span className="text-rose-500 font-bold">*</span>
          </label>
          <select
            id="url-user-state"
            value={userState}
            onChange={(e) => setUserState(e.target.value)}
            className={`w-full border rounded-2xl px-3.5 py-2.5 text-xs sm:text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500 cursor-pointer font-medium transition-all ${
              userState === 'paid' 
                ? 'border-rose-500 text-rose-900 bg-rose-50 dark:border-rose-600 dark:text-rose-300 dark:bg-rose-950/30' 
                : userState === 'entered_credentials'
                ? 'border-amber-500 text-amber-950 bg-amber-50 dark:border-amber-600 dark:text-amber-300 dark:bg-amber-950/30' 
                : 'bg-slate-50/80 text-slate-900 border-slate-200 dark:bg-night-950/80 dark:text-slate-200 dark:border-night-border'
            }`}
          >
            <option value="received">{t(lang, 'urlSitReceived', '1. I have NOT clicked it yet (Only received the link)')}</option>
            <option value="clicked">{t(lang, 'urlSitClicked', '2. I clicked the link and opened the website')}</option>
            <option value="entered_credentials">{t(lang, 'urlSitEntered', '3. I entered NetBanking password, OTP, or card numbers')}</option>
            <option value="paid">{t(lang, 'urlSitPaid', '4. I transferred money / authorized payment via UPI/Bank (EMERGENCY)')}</option>
          </select>
        </div>

        {/* Primary Action Button */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pt-4 border-t border-slate-200 dark:border-night-border">
          <button
            type="submit"
            id="analyze-url-btn"
            disabled={isAnalyzing}
            className="w-full sm:w-auto inline-flex items-center justify-center space-x-2 px-8 py-3 bg-slate-900 hover:bg-slate-800 text-white dark:bg-gradient-to-r dark:from-cyan-600 dark:to-indigo-600 dark:hover:from-cyan-500 dark:hover:to-indigo-500 font-bold rounded-xl text-sm shadow-luxury-glow transition-all duration-150 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
          >
            {isAnalyzing ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin text-current" />
                <span>{t(lang, 'scanningThreatFeeds', 'Scanning Threat Intelligence Feeds...')}</span>
              </>
            ) : (
              <>
                <Search className="w-4 h-4 text-current" strokeWidth={2.4} />
                <span>{t(lang, 'inspectLinkSafety', 'Inspect Link Safety')}</span>
              </>
            )}
          </button>

          <span className="text-[11px] text-slate-500 dark:text-slate-400">
            {t(lang, 'urlSafeSandboxNotice', 'Queries SafeBrowsing, PhishTank & PhishStats with zero device footprint.')}
          </span>
        </div>
      </form>
    </div>
  );
}
