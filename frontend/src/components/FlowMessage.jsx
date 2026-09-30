import React, { useState, useCallback, useRef } from 'react';
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
  FlaskConical,
  Mic,
  MicOff
} from 'lucide-react';
import { PRESET_SCENARIOS } from '../data/presets';
import { t } from '../i18n/translations';
import { useVoiceInput } from '../hooks/useVoiceInput';

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

  /**
   * Voice-to-text state — two refs, zero race conditions:
   *
   *   committedRef  — everything that is "locked in":
   *                   • pre-existing typed / pasted text (captured at the moment recording starts)
   *                   • each finalised speech phrase appended as it arrives
   *
   *   interimRef    — the current in-flight partial phrase being streamed live.
   *                   Replaced on every interim event, cleared when a final arrives.
   *
   * Display formula (always):  textarea = committedRef + ' ' + interimRef
   */
  const committedRef = useRef('');
  const interimRef   = useRef('');

  const flushToTextarea = useCallback(() => {
    const base   = committedRef.current;
    const live   = interimRef.current;
    const joined = base && live ? base + ' ' + live
                 : base         ? base
                 :                live;
    setMessage(joined);
  }, []);

  const handleTranscript = useCallback((text, isFinal) => {
    if (isFinal) {
      // Lock the phrase into committed text, clear the interim slot
      committedRef.current = committedRef.current
        ? committedRef.current + ' ' + text
        : text;
      interimRef.current = '';
    } else {
      // Live-stream: just update the interim slot (overwrite the previous partial)
      interimRef.current = text;
    }
    flushToTextarea();
    setValidationError(null);
  }, [flushToTextarea]);

  const { isListening, status: voiceStatus, isSupported: voiceSupported, toggle: toggleVoiceRaw } =
    useVoiceInput({ onTranscript: handleTranscript, lang });

  /**
   * Wrap toggle so that when recording STARTS we snapshot whatever is currently
   * in the textarea into committedRef. This means any pre-existing typed / pasted
   * text is preserved as the base and voice content appends after it.
   */
  const toggleVoice = useCallback(() => {
    if (!isListening) {
      // Snapshot current textarea content as the committed base
      setMessage((current) => {
        committedRef.current = current;
        interimRef.current   = '';
        return current; // no visual change, just capture
      });
    } else {
      // Stopping: freeze whatever is displayed (interim becomes committed)
      setMessage((current) => {
        committedRef.current = current;
        interimRef.current   = '';
        return current;
      });
    }
    toggleVoiceRaw();
  }, [isListening, toggleVoiceRaw]);

  // Derive the status hint shown below the textarea
  const voiceHint = (() => {
    if (!voiceSupported)                      return t(lang, 'voiceUnsupported', 'Voice input not supported in this browser.');
    if (voiceStatus === 'listening')          return t(lang, 'voiceListening', 'Listening — Tap to stop');
    if (voiceStatus === 'error_permission')   return t(lang, 'voiceDenied', 'Microphone access denied.');
    if (voiceStatus === 'error_no_speech')    return t(lang, 'voiceNoSpeech', 'No speech detected. Tap mic to retry.');
    if (voiceStatus === 'error_network')      return t(lang, 'voiceNoSpeech', 'No speech detected. Check connection.');
    if (voiceStatus === 'error_generic')      return t(lang, 'voiceNoSpeech', 'Recognition error. Tap mic to retry.');
    return null; // idle — show nothing
  })();

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
      <form onSubmit={handleFormSubmit} noValidate className="clean-card clean-card-hover p-6 shadow-sm space-y-5">
        {/* Textarea Header with Tools */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <label htmlFor="flow-message-input" className="text-xs font-bold text-slate-900 dark:text-slate-100">
              {t(lang, 'messageContent', 'Message Content')} <span className="text-rose-500 font-bold">*</span>
            </label>
            <div className="flex items-center space-x-2">
              <button
                type="button"
                onClick={handlePaste}
                className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-slate-200 dark:bg-surface-dark-hover dark:hover:bg-surface-dark-hover text-slate-700 dark:text-slate-300 text-xs font-semibold transition-colors cursor-pointer border border-slate-200 dark:border-border-dark"
                title="Paste from clipboard"
              >
                <ClipboardPaste className="w-3.5 h-3.5 text-accent dark:text-emerald-400" />
                <span>{t(lang, 'paste', 'Paste')}</span>
              </button>
              <button
                type="button"
                onClick={handleClear}
                className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-slate-200 dark:bg-surface-dark-hover dark:hover:bg-surface-dark-hover text-slate-700 dark:text-slate-300 text-xs font-semibold transition-colors cursor-pointer border border-slate-200 dark:border-border-dark"
                title="Clear input"
              >
                <Eraser className="w-3.5 h-3.5 text-slate-400" />
                <span>{t(lang, 'clear', 'Clear')}</span>
              </button>
              <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400 pl-1">
                {message.length} {t(lang, 'chars', 'chars')}
              </span>
            </div>
          </div>

          {/* Textarea wrapped in a relative container for mic button positioning */}
          <div className="relative">
            <textarea
              id="flow-message-input"
              rows={4}
              value={message}
              onChange={(e) => {
                setMessage(e.target.value);
                if (validationError) setValidationError(null);
              }}
              placeholder={t(lang, 'msgPlaceholder', 'Paste suspicious SMS, WhatsApp message, email, or select an example above...')}
              className={`w-full bg-slate-50/80 text-slate-900 placeholder-slate-400 border rounded-2xl p-3.5 pb-10 text-sm focus:outline-none focus:ring-2 focus:ring-accent/30 focus:border-emerald-700 dark:bg-surface-dark/80 dark:text-slate-100 dark:placeholder-slate-500 transition-all font-sans leading-relaxed resize-y ${
                validationError ? 'border-rose-500 ring-1 ring-rose-500' : 'border-slate-200 dark:border-border-dark'
              }`}
            />

            {/* ─── Microphone button — bottom-left of textarea, icon-only ─── */}
            {voiceSupported ? (
              <button
                type="button"
                onClick={toggleVoice}
                disabled={!voiceSupported}
                aria-label={isListening
                  ? t(lang, 'voiceListening', 'Listening — Tap to stop')
                  : t(lang, 'voiceInputLabel', 'Speak your message')}
                title={isListening
                  ? t(lang, 'voiceListening', 'Listening — Tap to stop')
                  : t(lang, 'voiceInputLabel', 'Speak your message')}
                className={`absolute bottom-2.5 left-2.5 p-1.5 rounded-lg transition-all duration-150 cursor-pointer focus:outline-none focus:ring-2 focus:ring-offset-1 ${
                  isListening
                    ? 'bg-rose-50 hover:bg-rose-100 text-rose-700 border border-rose-300 dark:bg-rose-950/40 dark:hover:bg-rose-950/60 dark:text-rose-400 dark:border-rose-700 focus:ring-rose-400 animate-pulse'
                    : 'bg-slate-100 hover:bg-slate-200 text-slate-600 border border-slate-200 dark:bg-surface-dark-hover dark:hover:bg-surface-dark-hover dark:text-slate-300 dark:border-border-dark focus:ring-accent'
                }`}
              >
                {isListening
                  ? <MicOff className="w-4 h-4" />
                  : <Mic className="w-4 h-4 text-accent dark:text-emerald-400" />}
              </button>
            ) : (
              <span
                className="absolute bottom-2.5 left-2.5 p-1.5 rounded-lg text-slate-400 dark:text-slate-600 border border-slate-200 dark:border-border-dark bg-slate-50 dark:bg-surface-dark cursor-not-allowed"
                title={t(lang, 'voiceUnsupported', 'Voice input not supported in this browser.')}
              >
                <Mic className="w-4 h-4" />
              </span>
            )}
          </div>

          {/* Voice status hint — only shown when not idle */}
          {voiceHint && (
            <p className={`mt-1.5 text-[11px] font-medium flex items-center space-x-1 ${
              voiceStatus === 'listening'
                ? 'text-rose-600 dark:text-rose-400'
                : voiceStatus === 'error_permission'
                ? 'text-amber-600 dark:text-amber-400'
                : 'text-slate-500 dark:text-slate-400'
            }`}>
              <span>{voiceHint}</span>
            </p>
          )}

          {validationError && (
            <p className="mt-1.5 text-xs text-rose-600 dark:text-rose-400 font-semibold flex items-center space-x-1">
              <AlertCircle className="w-3.5 h-3.5 inline mr-1 flex-shrink-0" />
              <span>{validationError}</span>
            </p>
          )}
        </div>

        {/* Channel & Situation Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label htmlFor="flow-channel-select" className="block text-xs font-bold text-slate-900 dark:text-slate-200 mb-1.5">
              {t(lang, 'commChannel', 'Communication Channel')}
            </label>
            <select
              id="flow-channel-select"
              value={channel}
              onChange={(e) => setChannel(e.target.value)}
              className="w-full bg-slate-50 text-slate-900 border border-slate-300 dark:border-border-dark rounded-xl px-3 py-2 text-xs sm:text-sm focus:outline-none focus:ring-2 focus:ring-accent dark:bg-surface-dark dark:text-slate-200 cursor-pointer"
            >
              <option value="sms">{t(lang, 'chanSms', 'SMS / Text Message')}</option>
              <option value="chat">{t(lang, 'chanChat', 'WhatsApp / Telegram / Chat')}</option>
              <option value="email">{t(lang, 'chanEmail', 'Email Message')}</option>
              <option value="text">{t(lang, 'chanText', 'General Document / Text')}</option>
            </select>
          </div>

          <div>
            <label htmlFor="flow-user-state" className="block text-xs font-bold text-slate-900 dark:text-slate-200 mb-1.5">
              {t(lang, 'yourSituation', 'Your Current Situation')} <span className="text-rose-500 font-bold">*</span>
            </label>
            <select
              id="flow-user-state"
              value={userState}
              onChange={(e) => setUserState(e.target.value)}
              className={`w-full border rounded-xl px-3 py-2 text-xs sm:text-sm focus:outline-none focus:ring-2 focus:ring-accent cursor-pointer font-medium ${
                userState === 'paid' 
                  ? 'border-rose-500 text-rose-900 bg-rose-50 dark:border-rose-600 dark:text-rose-300 dark:bg-rose-950/30' 
                  : userState === 'entered_credentials'
                  ? 'border-amber-500 text-amber-950 bg-amber-50 dark:border-amber-600 dark:text-amber-300 dark:bg-amber-950/30'
                  : 'bg-slate-50 text-slate-900 border-slate-300 dark:bg-surface-dark dark:text-slate-200 dark:border-border-dark'
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
            className="flex items-center space-x-1.5 text-xs text-slate-600 hover:text-accent dark:text-slate-400 dark:hover:text-emerald-400 transition-colors focus:outline-none cursor-pointer font-semibold"
          >
            <LinkIcon className="w-3.5 h-3.5 text-accent" />
            <span>{t(lang, 'addUrlsOptional', 'Additional Web Links (Optional)')}</span>
            {showUrlField ? <ChevronUp className="w-3 h-3 ml-1" /> : <ChevronDown className="w-3 h-3 ml-1" />}
          </button>

          {showUrlField && (
            <div className="mt-2">
              <textarea
                id="flow-urls-input"
                rows={2}
                value={urls}
                onChange={(e) => setUrls(e.target.value)}
                placeholder="https://sbi-kyc-verify-urgent.com/login"
                className="w-full bg-slate-50 text-slate-900 placeholder-slate-400 border border-slate-300 dark:border-border-dark rounded-xl p-3 text-xs font-mono focus:outline-none focus:ring-2 focus:ring-accent dark:bg-surface-dark dark:text-slate-100 dark:placeholder-slate-600"
              />
            </div>
          )}
        </div>

        {/* Primary Action Row with Luxury Gradient Button & Zero PII note */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pt-4 border-t border-slate-200 dark:border-border-dark">
          <button
            type="submit"
            id="analyze-btn"
            disabled={isAnalyzing}
            className="w-full sm:w-auto inline-flex items-center justify-center space-x-2 px-8 py-3 bg-slate-900 hover:bg-slate-800 text-white dark:bg-gradient-to-r dark:from-accent dark:to-accent-hover dark:hover:from-accent dark:hover:to-emerald-300 font-bold rounded-xl text-sm shadow-card-elevated transition-all duration-150 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
          >
            {isAnalyzing ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin text-current" />
                <span>{t(lang, 'runningTriage', 'Running Forensic Triage...')}</span>
              </>
            ) : (
              <>
                <Search className="w-4 h-4 text-current" strokeWidth={2.4} />
                <span>{t(lang, 'investigateMsg', 'Investigate Message')}</span>
              </>
            )}
          </button>

          <div className="flex items-center space-x-2 text-[11px] text-slate-500 dark:text-slate-400">
            <ShieldCheck className="w-4 h-4 text-emerald-500 flex-shrink-0" />
            <span>{t(lang, 'zeroPiiNotice', 'Zero PII Retention: Ephemeral analysis only. Aadhaar & OTP numbers are expunged prior to evaluation.')}</span>
          </div>
        </div>
      </form>
    </div>
  );
}
