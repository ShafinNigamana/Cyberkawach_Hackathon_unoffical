import React, { useState } from 'react';
import { 
  ArrowLeft, 
  MessageSquare, 
  ClipboardPaste, 
  Eraser, 
  Search, 
  Loader2, 
  AlertCircle, 
  ChevronDown, 
  ChevronUp, 
  Link as LinkIcon, 
  ShieldCheck,
  FlaskConical
} from 'lucide-react';
import { PRESET_SCENARIOS } from '../data/presets';
import { t } from '../i18n/translations';

export default function FlowMessage({ 
  onBack, 
  onSubmit, 
  isAnalyzing, 
  initialMessage = '', 
  initialUrls = '',
  initialState = 'received',
  initialChannel = 'sms',
  lang = 'en'
}) {
  const [message, setMessage] = useState(initialMessage);
  const [urls, setUrls] = useState(initialUrls);
  const [channel, setChannel] = useState(initialChannel);
  const [userState, setUserState] = useState(initialState);
  const [showUrlField, setShowUrlField] = useState(Boolean(initialUrls));
  const [validationError, setValidationError] = useState(null);

  const getPresetTitle = (preset) => {
    const key = `preset_${preset.id.replace(/-/g, '_')}`;
    return t(lang, key, preset.title);
  };

  const handlePaste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        setMessage((prev) => (prev ? prev + '\n' : '') + text);
        setValidationError(null);
      }
    } catch {
      // Fallback
    }
  };

  const handleClear = () => {
    setMessage('');
    setUrls('');
    setValidationError(null);
  };

  const handleSelectPreset = (preset) => {
    setMessage(preset.message || '');
    setUrls(preset.urls || '');
    setChannel(preset.type || 'sms');
    setUserState(preset.state || 'received');
    setValidationError(null);
  };

  const handleFormSubmit = (e) => {
    if (e) e.preventDefault();
    if (!message || !message.trim()) {
      setValidationError(t(lang, 'msgPlaceholder', 'Please enter or paste suspicious message text to analyze.'));
      return;
    }
    setValidationError(null);
    onSubmit({
      message: message.trim(),
      urls: urls,
      input_type: channel,
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
          {t(lang, 'flowMsgBreadcrumb', 'Flow: Check Message / SMS')}
        </span>
      </div>

      {/* ─── Flow Title & Instructions ─── */}
      <div className="space-y-1">
        <div className="flex items-center space-x-2">
          <div className="w-8 h-8 rounded-lg bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900 flex items-center justify-center flex-shrink-0">
            <MessageSquare className="w-4 h-4" />
          </div>
          <h2 className="text-xl font-extrabold text-slate-900 dark:text-white">
            {t(lang, 'flowMsgTitle', 'Analyze Suspicious Message or SMS')}
          </h2>
        </div>
        <p className="text-xs text-slate-600 dark:text-slate-400 pl-10">
          {t(lang, 'flowMsgDesc', 'Paste the message text or select an example scenario below to verify its authenticity, urgency tactics, and fraudulent links.')}
        </p>
      </div>

      {/* ─── Example Typologies Shortcuts ─── */}
      <div className="bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-3 space-y-2">
        <div className="flex items-center space-x-1.5 text-xs font-bold text-slate-700 dark:text-slate-300">
          <FlaskConical className="w-3.5 h-3.5 text-slate-600 dark:text-slate-400" />
          <span>{t(lang, 'quickScenarios', 'Quick Benchmark Scenarios:')}</span>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {PRESET_SCENARIOS.map((preset) => (
            <button
              key={preset.id}
              type="button"
              onClick={() => handleSelectPreset(preset)}
              className="inline-flex items-center space-x-1 px-2.5 py-1 rounded bg-white hover:bg-slate-100 dark:bg-slate-800 dark:hover:bg-slate-700 border border-slate-300 dark:border-slate-700 text-xs text-slate-800 dark:text-slate-200 font-medium transition-colors cursor-pointer shadow-xs"
            >
              <span>{getPresetTitle(preset)}</span>
            </button>
          ))}
        </div>
      </div>

      {/* ─── Dedicated Message Form ─── */}
      <form onSubmit={handleFormSubmit} noValidate className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 shadow-xs space-y-4">
        {/* Textarea Header with Tools */}
        <div>
          <div className="flex items-center justify-between mb-1.5">
            <label htmlFor="flow-message-input" className="text-xs font-bold text-slate-900 dark:text-slate-200">
              {t(lang, 'messageContent', 'Message Content')} <span className="text-red-600 font-bold">*</span>
            </label>
            <div className="flex items-center space-x-2">
              <button
                type="button"
                onClick={handlePaste}
                className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 text-xs font-medium transition-colors cursor-pointer"
                title="Paste from clipboard"
              >
                <ClipboardPaste className="w-3 h-3 text-slate-600 dark:text-slate-400" />
                <span>{t(lang, 'paste', 'Paste')}</span>
              </button>
              <button
                type="button"
                onClick={handleClear}
                className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 text-xs font-medium transition-colors cursor-pointer"
                title="Clear input"
              >
                <Eraser className="w-3 h-3 text-slate-500" />
                <span>{t(lang, 'clear', 'Clear')}</span>
              </button>
              <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400 pl-1">
                {message.length} {t(lang, 'chars', 'chars')}
              </span>
            </div>
          </div>

          <textarea
            id="flow-message-input"
            rows={4}
            value={message}
            onChange={(e) => {
              setMessage(e.target.value);
              if (validationError) setValidationError(null);
            }}
            placeholder={t(lang, 'msgPlaceholder', 'Paste suspicious SMS, WhatsApp message, email, or select an example above...')}
            className={`w-full bg-slate-50 text-slate-900 placeholder-slate-400 border rounded-lg p-3 text-sm focus:outline-none focus:ring-2 focus:ring-slate-900 focus:border-slate-900 dark:bg-slate-950 dark:text-slate-100 dark:placeholder-slate-500 transition-all font-sans leading-relaxed resize-y ${
              validationError ? 'border-red-500 ring-1 ring-red-500' : 'border-slate-300 dark:border-slate-700'
            }`}
          />

          {validationError && (
            <p className="mt-1 text-xs text-red-600 dark:text-red-400 font-semibold flex items-center space-x-1">
              <AlertCircle className="w-3.5 h-3.5 inline mr-1 flex-shrink-0" />
              <span>{validationError}</span>
            </p>
          )}
        </div>

        {/* Channel & Situation Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div>
            <label htmlFor="flow-channel-select" className="block text-xs font-bold text-slate-900 dark:text-slate-300 mb-1">
              {t(lang, 'commChannel', 'Communication Channel')}
            </label>
            <select
              id="flow-channel-select"
              value={channel}
              onChange={(e) => setChannel(e.target.value)}
              className="w-full bg-slate-50 text-slate-900 border border-slate-300 rounded-lg px-2.5 py-1.5 text-xs sm:text-sm focus:outline-none focus:ring-2 focus:ring-slate-900 dark:bg-slate-950 dark:text-slate-200 dark:border-slate-700 cursor-pointer"
            >
              <option value="sms">{t(lang, 'chanSms', 'SMS / Text Message')}</option>
              <option value="chat">{t(lang, 'chanChat', 'WhatsApp / Telegram / Chat')}</option>
              <option value="email">{t(lang, 'chanEmail', 'Email Message')}</option>
              <option value="text">{t(lang, 'chanText', 'General Document / Text')}</option>
            </select>
          </div>

          <div>
            <label htmlFor="flow-user-state" className="block text-xs font-bold text-slate-900 dark:text-slate-300 mb-1">
              {t(lang, 'yourSituation', 'Your Current Situation')} <span className="text-red-600 font-bold">*</span>
            </label>
            <select
              id="flow-user-state"
              value={userState}
              onChange={(e) => setUserState(e.target.value)}
              className={`w-full border rounded-lg px-2.5 py-1.5 text-xs sm:text-sm focus:outline-none focus:ring-2 focus:ring-slate-900 cursor-pointer font-medium ${
                userState === 'paid' 
                  ? 'border-red-600 text-red-900 bg-red-50 dark:border-red-600 dark:text-red-300 dark:bg-red-950/20' 
                  : userState === 'entered_credentials'
                  ? 'border-amber-600 text-amber-950 bg-amber-50 dark:border-amber-600 dark:text-amber-300 dark:bg-amber-950/20'
                  : 'bg-slate-50 text-slate-900 border-slate-300 dark:bg-slate-950 dark:text-slate-200 dark:border-slate-700'
              }`}
            >
              <option value="received">{t(lang, 'sitReceived', '1. I only received this message (No action taken yet)')}</option>
              <option value="clicked">{t(lang, 'sitClicked', '2. I clicked on a link or opened the website')}</option>
              <option value="entered_credentials">{t(lang, 'sitEntered', '3. I entered my passwords, OTP, or personal details')}</option>
              <option value="paid">{t(lang, 'sitPaid', '4. I transferred money / authorized a payment (EMERGENCY)')}</option>
            </select>
          </div>
        </div>

        {/* Collapsible Secondary URLs Input */}
        <div>
          <button
            type="button"
            onClick={() => setShowUrlField(!showUrlField)}
            className="flex items-center space-x-1.5 text-xs text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white transition-colors focus:outline-none cursor-pointer"
          >
            <LinkIcon className="w-3.5 h-3.5" />
            <span className="font-semibold">{t(lang, 'addUrlsOptional', 'Additional Web Links (Optional)')}</span>
            {showUrlField ? <ChevronUp className="w-3 h-3 ml-1" /> : <ChevronDown className="w-3 h-3 ml-1" />}
          </button>

          {showUrlField && (
            <div className="mt-1.5">
              <textarea
                id="flow-urls-input"
                rows={2}
                value={urls}
                onChange={(e) => setUrls(e.target.value)}
                placeholder="https://sbi-kyc-verify-urgent.com/login"
                className="w-full bg-slate-50 text-slate-900 placeholder-slate-400 border border-slate-300 rounded-lg p-2 text-xs font-mono focus:outline-none focus:ring-2 focus:ring-slate-900 dark:bg-slate-950 dark:text-slate-100 dark:placeholder-slate-600 dark:border-slate-700"
              />
            </div>
          )}
        </div>

        {/* Primary Action Row with Monochrome Button & Zero PII note */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-3 border-t border-slate-200 dark:border-slate-800">
          <button
            type="submit"
            id="analyze-btn"
            disabled={isAnalyzing}
            className="w-full sm:w-auto inline-flex items-center justify-center space-x-2 px-7 py-2.5 bg-slate-900 hover:bg-slate-800 text-white dark:bg-slate-100 dark:hover:bg-white dark:text-slate-900 font-bold rounded-lg text-sm shadow-sm transition-all duration-150 active:scale-[0.99] disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
          >
            {isAnalyzing ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin text-white dark:text-slate-900" />
                <span>{t(lang, 'runningTriage', 'Running Forensic Triage...')}</span>
              </>
            ) : (
              <>
                <Search className="w-4 h-4 text-white dark:text-slate-900" strokeWidth={2.4} />
                <span>{t(lang, 'investigateMsg', 'Investigate Message')}</span>
              </>
            )}
          </button>

          <div className="flex items-center space-x-2 text-[11px] text-slate-500 dark:text-slate-400">
            <ShieldCheck className="w-4 h-4 text-emerald-600 dark:text-emerald-400 flex-shrink-0" />
            <span>{t(lang, 'zeroPiiNotice', 'Zero PII Retention: Ephemeral analysis only. Aadhaar & OTP numbers are expunged prior to evaluation.')}</span>
          </div>
        </div>
      </form>
    </div>
  );
}
