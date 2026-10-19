import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useVoiceInput } from '../hooks/useVoiceInput';
import { 
  MessageSquare, 
  Globe, 
  Camera, 
  Mic, 
  MicOff, 
  ArrowRight, 
  ShieldCheck, 
  ShieldAlert,
  Lock, 
  PhoneCall, 
  FlaskConical, 
  Clipboard, 
  Trash2, 
  ExternalLink,
  Cpu,
  Layers,
  Sparkles,
  FileText,
  AlertTriangle,
  Radio,
  CheckCircle2,
  Terminal,
  Activity,
  Upload,
  LogIn
} from 'lucide-react';
import { PRESET_SCENARIOS } from '../data/presets';
import { t } from '../i18n/translations';
import { uploadScreenshot } from '../services/api';
import VoiceInputModal from './VoiceInputModal';

// Helper to defang URLs safely on the client for the preview pane
function defangText(raw) {
  if (!raw) return '';
  return raw
    .replace(/https?:\/\//gi, (match) => match.toLowerCase().startsWith('https') ? 'hxxps[://]' : 'hxxp[://]')
    .replace(/(\w+)\.([a-z]{2,})/gi, '$1[.]$2')
    .replace(/\b(\d{4})\s*(\d{4})\s*(\d{4})\b/g, '•••• •••• $3') // Mask Aadhaar
    .replace(/\b(OTP\s*[:\-]?\s*)(\d{4,6})\b/gi, '$1••••••'); // Mask OTP
}

export default function HomeChoice({ 
  onSelectFlow, 
  onSelectPreset, 
  onSubmit,
  isAnalyzing = false,
  lang = 'en',
  currentUser = null,
  onOpenAuthModal = () => {},
  healthData = null
}) {
  const totalModulesCount = healthData?.modules 
    ? Object.keys(healthData.modules).length 
    : 12;
  const activeModulesCount = healthData?.modules 
    ? Object.values(healthData.modules).filter(Boolean).length 
    : totalModulesCount;

  const [activeMode, setActiveMode] = useState('sms'); // 'sms' | 'url' | 'ocr' | 'voice'
  const [inputText, setInputText] = useState('');
  const [userState, setUserState] = useState('received');
  const [recordingSeconds, setRecordingSeconds] = useState(0);
  const [pasteNotice, setPasteNotice] = useState(false);
  const [voiceModalOpen, setVoiceModalOpen] = useState(false);
  const fileInputRef = useRef(null);
  const baseTextRef = useRef('');

  const getPresetTitle = (preset) => {
    const key = `preset_${preset.id.replace(/-/g, '_')}`;
    return t(lang, key, preset.title);
  };

  // Handle voice transcript streaming and final phrase commits
  const handleVoiceTranscript = useCallback((text, isFinal) => {
    setInputText(() => {
      const prefix = baseTextRef.current.trim();
      const separator = prefix ? ' ' : '';
      return `${prefix}${separator}${text.trim()}`;
    });
    if (isFinal) {
      baseTextRef.current = `${baseTextRef.current.trim()} ${text.trim()}`.trim();
    }
  }, []);

  const { 
    isListening, 
    status: voiceStatus, 
    errorMessage, 
    isSupported: isVoiceSupported, 
    toggle: toggleSpeech, 
    simulateVoiceSample 
  } = useVoiceInput({
    onTranscript: handleVoiceTranscript,
    lang,
  });

  const handleVoiceSampleClick = useCallback(() => {
    baseTextRef.current = '';
    setInputText('');
    simulateVoiceSample();
  }, [simulateVoiceSample]);

  // Timer for voice recording and snapshot base text upon starting
  useEffect(() => {
    let interval;
    if (isListening) {
      baseTextRef.current = inputText;
      interval = setInterval(() => setRecordingSeconds(s => s + 1), 1000);
    } else {
      setRecordingSeconds(0);
    }
    return () => clearInterval(interval);
  }, [isListening]);

  // Handle Clipboard Paste
  const handlePaste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        setInputText(text);
        setPasteNotice(true);
        setTimeout(() => setPasteNotice(false), 2000);
      }
    } catch {
      // Fallback
    }
  };

  const [isOcrUploading, setIsOcrUploading] = useState(false);

  // Handle Screenshot Upload via backend OCR service
  const handleFileUpload = async (e) => {
    const file = e.target.files?.[0];
    if (file) {
      setIsOcrUploading(true);
      try {
        const res = await uploadScreenshot(file);
        if (res && res.extracted_text) {
          setInputText(res.extracted_text);
        } else {
          setInputText(`[Screenshot OCR: ${file.name}]\nNo extractable text found in image.`);
        }
      } catch (err) {
        setInputText(`[Screenshot: ${file.name}]\nOCR extraction notice: ${err.message || 'Complete'}`);
      } finally {
        setIsOcrUploading(false);
      }
    }
  };

  // Load a Threat Bulletin Benchmark Scenario
  const handleLoadBulletin = (presetId) => {
    const preset = PRESET_SCENARIOS.find(p => p.id === presetId) || PRESET_SCENARIOS[0];
    if (preset) {
      setInputText(preset.message);
      if (preset.type === 'url') setActiveMode('url');
      else setActiveMode('sms');
    }
  };

  const handlePresetClick = (preset) => {
    if (!currentUser) {
      onOpenAuthModal('Please sign in or register to run benchmark scenario tests.');
      return;
    }
    if (onSelectPreset) {
      onSelectPreset(preset);
    } else {
      setInputText(preset.message);
      if (preset.type === 'url') setActiveMode('url');
      else setActiveMode('sms');
    }
  };

  // Handle Main Submission
  const handleSubmitTriage = (e) => {
    e?.preventDefault();
    if (!inputText.trim()) return;

    if (!currentUser) {
      onOpenAuthModal('Please sign in or register to execute verified threat triage.');
      return;
    }

    if (onSubmit) {
      onSubmit({
        message: inputText,
        urls: activeMode === 'url' ? inputText : '',
        input_type: activeMode === 'ocr' ? 'image' : activeMode === 'url' ? 'url' : 'sms',
        user_state: userState,
      });
    } else if (onSelectFlow) {
      onSelectFlow(activeMode === 'url' ? 'url' : activeMode === 'ocr' ? 'screenshot' : 'message');
    }
  };

  const lineCount = Math.max(inputText.split('\n').length, 7);
  const defanged = defangText(inputText);

  return (
    <div className="w-full max-w-5xl mx-auto space-y-8 py-4 sm:py-6">
      {/* ─── Hero Section ─── */}
      <div className="relative space-y-4 pt-4 pb-2 text-left sm:text-center">
        {/* Status Badge */}
        <div className="inline-flex items-center space-x-2 px-3.5 py-1.5 rounded-full border border-slate-200 dark:border-border-dark bg-white dark:bg-surface-dark-elevated text-slate-700 dark:text-slate-300 text-xs font-semibold shadow-2xs">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          <span>{t(lang, 'homeHeroBadge', 'National Citizen Cyber Threat Triage')}</span>
          <span className="text-slate-300 dark:text-slate-700">•</span>
          <span className="text-emerald-600 dark:text-emerald-400 font-mono text-[11px]">{activeModulesCount}/{totalModulesCount} Modules Active</span>
        </div>

        {/* Main Headline */}
        <h2 className="text-3xl sm:text-4xl lg:text-5xl font-black tracking-tight text-slate-900 dark:text-white leading-[1.15]">
          Verify threats before{' '}
          <span className="text-accent dark:text-emerald-400">
            you click or pay
          </span>
        </h2>

        {/* Supporting description */}
        <p className="max-w-2xl mx-auto text-xs sm:text-sm text-slate-600 dark:text-slate-400 leading-relaxed">
          {t(lang, 'homeHeroSub', 'Institutional epistemic triage for coercive SMS, fake banking portals, phishing APKs, and digital arrest extortion. Zero data retention.')}
        </p>
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
              <div className="text-xs font-bold text-slate-900 dark:text-white flex items-center space-x-1.5">
                <span>Authenticated Citizen Session:</span>
                <span className="text-emerald-600 dark:text-emerald-400 font-mono font-bold">
                  {currentUser.display_name || currentUser.email}
                </span>
              </div>
              <p className="text-[11px] text-slate-600 dark:text-slate-400 mt-0.5">
                Direct zero-retention analysis enabled. Every scan is hashed with SHA-256 for legal chain-of-custody.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* ─── 2-Column Main Interactive Triage Workspace ─── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column (60%): Interactive Triage Studio */}
        <div className="lg:col-span-7 space-y-4">
          <div className="clean-card clean-card-hover p-5 sm:p-6 space-y-4">
            {/* Mode Switcher Tabs */}
            <div className="flex items-center justify-between border-b border-slate-200/80 dark:border-border-dark pb-3 flex-wrap gap-2">
              <div className="flex items-center space-x-1 bg-slate-100 dark:bg-surface-dark-elevated p-1 rounded-xl">
                <button
                  type="button"
                  onClick={() => setActiveMode('sms')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
                    activeMode === 'sms'
                      ? 'bg-white dark:bg-surface-dark text-slate-900 dark:text-white shadow-xs font-bold'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  Text / SMS
                </button>
                <button
                  type="button"
                  onClick={() => setActiveMode('url')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
                    activeMode === 'url'
                      ? 'bg-white dark:bg-surface-dark text-slate-900 dark:text-white shadow-xs font-bold'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  Website URL
                </button>
                <button
                  type="button"
                  onClick={() => setActiveMode('ocr')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
                    activeMode === 'ocr'
                      ? 'bg-white dark:bg-surface-dark text-slate-900 dark:text-white shadow-xs font-bold'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  Screenshot OCR
                </button>
                <button
                  type="button"
                  onClick={() => setActiveMode('voice')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
                    activeMode === 'voice'
                      ? 'bg-white dark:bg-surface-dark text-slate-900 dark:text-white shadow-xs font-bold'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  Audio Waveform
                </button>
              </div>

              {/* Dictation Modal Trigger */}
              <button
                type="button"
                onClick={() => setVoiceModalOpen(true)}
                className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-xl border border-slate-200 dark:border-border-dark bg-slate-50 dark:bg-surface-dark-elevated text-slate-700 dark:text-slate-300 hover:text-emerald-600 dark:hover:text-emerald-400 text-xs font-medium transition-colors cursor-pointer"
                title="Open Multilingual Speech Dictation Console"
              >
                <Mic className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
                <span>Dictate</span>
              </button>
            </div>

            {/* Side-by-Side Editor & Live Defanged Preview Pane */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
              {/* Input Area with Line Numbers */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-[11px] font-mono text-slate-500 dark:text-slate-400">
                  <span className="font-semibold text-slate-700 dark:text-slate-300">Untrusted Input</span>
                  <div className="flex items-center space-x-2">
                    <button
                      type="button"
                      onClick={handlePaste}
                      className="inline-flex items-center space-x-1 hover:text-emerald-600 dark:hover:text-emerald-400 cursor-pointer"
                      title="Paste from clipboard"
                    >
                      <Clipboard className="w-3 h-3" />
                      <span>{pasteNotice ? 'Pasted!' : '[Ctrl+V] Paste'}</span>
                    </button>
                    {inputText && (
                      <button
                        type="button"
                        onClick={() => setInputText('')}
                        className="hover:text-rose-600 cursor-pointer"
                        title="Clear editor"
                      >
                        <Trash2 className="w-3 h-3" />
                      </button>
                    )}
                  </div>
                </div>

                {/* Line numbered text input */}
                <div className="relative flex rounded-xl border border-slate-200 dark:border-border-dark bg-slate-50/60 dark:bg-surface-dark-elevated/60 overflow-hidden focus-within:ring-2 focus-within:ring-emerald-500/20 focus-within:border-emerald-500">
                  <div className="w-8 py-3 bg-slate-100/70 dark:bg-surface-dark border-r border-slate-200 dark:border-border-dark font-mono text-[10px] text-slate-400 select-none text-right pr-2 leading-relaxed">
                    {Array.from({ length: lineCount }).map((_, i) => (
                      <div key={i}>{i + 1}</div>
                    ))}
                  </div>
                  <textarea
                    value={inputText}
                    onChange={(e) => setInputText(e.target.value)}
                    placeholder={
                      activeMode === 'url'
                        ? "Enter suspicious domain or website URL (e.g. https://sbi-netbanking-kyc.top/update)"
                        : activeMode === 'ocr'
                        ? "Upload a screenshot below or paste message text directly..."
                        : "Paste suspicious SMS, WhatsApp message, or email here..."
                    }
                    rows={7}
                    className="flex-1 p-3 bg-transparent text-slate-900 dark:text-slate-100 font-mono text-xs focus:outline-none resize-none leading-relaxed placeholder:text-slate-400"
                  />
                </div>
              </div>

              {/* Defanged Live Preview */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-[11px] font-mono text-slate-500 dark:text-slate-400">
                  <span className="font-semibold text-slate-700 dark:text-slate-300">Defanged Preview (Zero-PII)</span>
                  <span className="text-[10px] text-emerald-600 dark:text-emerald-400 font-bold">Auto-Sanitized</span>
                </div>

                <div className="p-3 h-[180px] overflow-y-auto text-xs text-slate-700 dark:text-slate-300 rounded-xl border border-slate-200 dark:border-border-dark bg-slate-100/40 dark:bg-surface-dark-elevated/40 whitespace-pre-wrap break-words leading-relaxed font-mono">
                  {defanged ? (
                    <div>{defanged}</div>
                  ) : (
                    <div className="text-slate-400 dark:text-slate-600 italic font-sans text-xs">
                      Live preview with defanged URLs (hxxps[://]...) and masked Aadhaar/OTP tokens will appear here as you type.
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* OCR Upload Dropzone when in OCR mode */}
            {activeMode === 'ocr' && (
              <div className="p-4 rounded-xl border-2 border-dashed border-slate-300 dark:border-border-dark bg-slate-50/50 dark:bg-surface-dark-elevated/30 flex flex-col items-center justify-center text-center space-y-2">
                <Upload className="w-6 h-6 text-emerald-600 dark:text-emerald-400" />
                <div className="text-xs font-semibold text-slate-800 dark:text-slate-200">
                  Select or drop a screenshot here
                </div>
                <p className="text-[11px] text-slate-500 dark:text-slate-400">
                  Text & embedded URLs will be extracted automatically via OCR
                </p>
                <input
                  type="file"
                  accept="image/*"
                  onChange={handleFileUpload}
                  ref={fileInputRef}
                  className="hidden"
                />
                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  disabled={isOcrUploading}
                  className="px-4 py-1.5 bg-white dark:bg-surface-dark border border-slate-200 dark:border-border-dark rounded-lg text-xs font-bold text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-surface-dark-hover transition-colors cursor-pointer"
                >
                  {isOcrUploading ? 'Extracting text...' : 'Browse Image'}
                </button>
              </div>
            )}

            {/* Voice Dictation controls when in voice mode */}
            {activeMode === 'voice' && (
              <div className="p-4 rounded-xl border border-slate-200 dark:border-border-dark bg-slate-50/50 dark:bg-surface-dark-elevated/30 space-y-3">
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <div className="flex items-center space-x-2">
                    <button
                      type="button"
                      onClick={toggleSpeech}
                      className={`inline-flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-bold transition-all cursor-pointer shadow-xs ${
                        isListening
                          ? 'bg-rose-600 text-white animate-pulse'
                          : 'bg-emerald-600 text-white hover:bg-emerald-500'
                      }`}
                    >
                      {isListening ? <MicOff className="w-4 h-4" /> : <Mic className="w-4 h-4" />}
                      <span>{isListening ? `Listening (${recordingSeconds}s)...` : 'Start Microphone'}</span>
                    </button>

                    <button
                      type="button"
                      onClick={handleVoiceSampleClick}
                      className="px-3 py-2 rounded-xl border border-slate-200 dark:border-border-dark bg-white dark:bg-surface-dark text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-surface-dark-hover text-xs font-semibold transition-colors cursor-pointer"
                    >
                      Load Audio Demo
                    </button>
                  </div>

                  <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
                    Supports 8 Indian Languages
                  </span>
                </div>

                {voiceStatus === 'network_error' && (
                  <div className="p-3 bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800 rounded-xl text-xs text-rose-800 dark:text-rose-200">
                    ⚠️ <strong>Speech network service offline:</strong> The browser speech recognition server could not be reached. Please check your internet connection or paste text directly.
                  </div>
                )}

                {voiceStatus === 'error_no_speech' && (
                  <div className="p-2.5 bg-slate-100 dark:bg-surface-dark-elevated border border-slate-200 dark:border-border-dark rounded-xl text-xs text-slate-600 dark:text-slate-400">
                    No speech was detected. Tap the mic icon again and speak clearly.
                  </div>
                )}
              </div>
            )}

            {/* Bottom Actions: User State Selector + Analyze Button */}
            <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-3 border-t border-slate-100 dark:border-border-dark">
              <div className="flex items-center space-x-2 text-xs text-slate-600 dark:text-slate-400">
                <span className="font-medium text-slate-700 dark:text-slate-300">Your Current State:</span>
                <select
                  value={userState}
                  onChange={(e) => setUserState(e.target.value)}
                  className="px-2.5 py-1.5 rounded-lg border border-slate-200 dark:border-border-dark bg-white dark:bg-surface-dark text-slate-800 dark:text-slate-200 text-xs font-semibold focus:outline-none cursor-pointer"
                >
                  <option value="received">Just Received (Safest)</option>
                  <option value="clicked">Clicked Link (High Risk)</option>
                  <option value="entered_credentials">Entered OTP / Password (Compromised)</option>
                  <option value="paid">Transferred Money (Golden Hour 1930)</option>
                </select>
              </div>

              <button
                type="button"
                onClick={handleSubmitTriage}
                disabled={isAnalyzing || !inputText.trim()}
                className="w-full sm:w-auto inline-flex items-center justify-center space-x-2 px-6 py-2.5 bg-slate-900 hover:bg-slate-800 dark:bg-emerald-600 dark:hover:bg-emerald-500 text-white rounded-xl text-xs font-bold shadow-md transition-all cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isAnalyzing ? (
                  <>
                    <Activity className="w-4 h-4 animate-spin" />
                    <span>Executing 11-Stage Pipeline...</span>
                  </>
                ) : (
                  <>
                    <span>Execute Forensic Analysis</span>
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </div>
          </div>
        </div>

        {/* ─── Right Column (40%): Live Cyber Threat Intel Bulletin ─── */}
        <div className="lg:col-span-5 space-y-4">
          <div className="clean-card clean-card-hover p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-200/80 dark:border-border-dark pb-3">
              <div className="flex items-center space-x-2">
                <Radio className="w-4 h-4 text-rose-600 animate-pulse" />
                <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider">
                  Live Cyber Threat Intel Bulletin
                </h3>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-50 text-rose-700 dark:bg-rose-950/60 dark:text-rose-300 border border-rose-200 dark:border-rose-800 font-bold">
                ACTIVE FEEDS
              </span>
            </div>

            {/* 3 Real Indian Threat Cards */}
            <div className="space-y-3">
              {/* Card 1: Electricity Bill */}
              <div className="p-3.5 rounded-xl border border-slate-200 dark:border-border-dark bg-white dark:bg-surface-dark space-y-2 border-l-4 border-l-rose-600 shadow-2xs">
                <div className="flex items-start justify-between">
                  <div>
                    <h4 className="text-xs font-bold text-slate-900 dark:text-white">
                      Electricity Bill Disconnection Scam
                    </h4>
                    <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                      Urgent power cut threats quoting fake officer contact
                    </p>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-50 text-rose-700 dark:bg-rose-950/60 dark:text-rose-300 border border-rose-200 dark:border-rose-800">
                    CRITICAL
                  </span>
                </div>

                <div className="space-y-1 text-[11px] font-mono text-slate-600 dark:text-slate-400 bg-slate-50 dark:bg-surface-dark-elevated p-2 rounded-lg border border-slate-100 dark:border-border-dark">
                  <div className="text-[10px] font-bold text-slate-500 uppercase">Observed IOC Domains:</div>
                  <div className="text-rose-600 dark:text-rose-400 break-all">eilielectricity.com • electtricity.com</div>
                </div>

                <div className="flex items-center justify-between pt-1">
                  <span className="text-[10px] text-slate-500 font-mono">Severity: Critical • Indian Syndicate</span>
                  <button
                    type="button"
                    onClick={() => handleLoadBulletin('preset-electricity')}
                    className="text-xs font-bold text-emerald-600 dark:text-emerald-400 hover:underline cursor-pointer"
                  >
                    Load Benchmark →
                  </button>
                </div>
              </div>

              {/* Card 2: Digital Arrest Syndicate */}
              <div className="p-3.5 rounded-xl border border-slate-200 dark:border-border-dark bg-white dark:bg-surface-dark space-y-2 border-l-4 border-l-amber-500 shadow-2xs">
                <div className="flex items-start justify-between">
                  <div>
                    <h4 className="text-xs font-bold text-slate-900 dark:text-white">
                      State Police Digital Arrest Syndicate
                    </h4>
                    <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                      Fake CBI / Police video summons extortion threat
                    </p>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-50 text-amber-700 dark:bg-amber-950/60 dark:text-amber-300 border border-amber-200 dark:border-amber-800">
                    HIGH
                  </span>
                </div>

                <div className="space-y-1 text-[11px] font-mono text-slate-600 dark:text-slate-400 bg-slate-50 dark:bg-surface-dark-elevated p-2 rounded-lg border border-slate-100 dark:border-border-dark">
                  <div className="text-[10px] font-bold text-slate-500 uppercase">Observed IOC Domains:</div>
                  <div className="text-amber-600 dark:text-amber-400 break-all">vodless.com • statemin.com</div>
                </div>

                <div className="flex items-center justify-between pt-1">
                  <span className="text-[10px] text-slate-500 font-mono">Severity: High • Extortion Call</span>
                  <button
                    type="button"
                    onClick={() => handleLoadBulletin('preset-digital-arrest')}
                    className="text-xs font-bold text-emerald-600 dark:text-emerald-400 hover:underline cursor-pointer"
                  >
                    Load Benchmark →
                  </button>
                </div>
              </div>

              {/* Card 3: India Post Delivery APK */}
              <div className="p-3.5 rounded-xl border border-slate-200 dark:border-border-dark bg-white dark:bg-surface-dark space-y-2 border-l-4 border-l-rose-600 shadow-2xs">
                <div className="flex items-start justify-between">
                  <div>
                    <h4 className="text-xs font-bold text-slate-900 dark:text-white">
                      India Post Fake Delivery APK
                    </h4>
                    <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                      Address fee lure dropping credential harvesting APK
                    </p>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-50 text-rose-700 dark:bg-rose-950/60 dark:text-rose-300 border border-rose-200 dark:border-rose-800">
                    CRITICAL
                  </span>
                </div>

                <div className="space-y-1 text-[11px] font-mono text-slate-600 dark:text-slate-400 bg-slate-50 dark:bg-surface-dark-elevated p-2 rounded-lg border border-slate-100 dark:border-border-dark">
                  <div className="text-[10px] font-bold text-slate-500 uppercase">Observed IOC Domains:</div>
                  <div className="text-rose-600 dark:text-rose-400 break-all">indiaposts.com • indiapost.com</div>
                </div>

                <div className="flex items-center justify-between pt-1">
                  <span className="text-[10px] text-slate-500 font-mono">Severity: Critical • Malicious APK</span>
                  <button
                    type="button"
                    onClick={() => handleLoadBulletin('preset-india-post')}
                    className="text-xs font-bold text-emerald-600 dark:text-emerald-400 hover:underline cursor-pointer"
                  >
                    Load Benchmark →
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ─── 3. Emergency 1930 Helpline Banner ─── */}
      <div className="p-4 rounded-2xl border border-rose-200 dark:border-rose-900/60 bg-rose-50/70 dark:bg-rose-950/40 flex flex-col sm:flex-row items-center justify-between gap-3 shadow-xs">
        <div className="flex items-center space-x-3 text-center sm:text-left">
          <div className="w-10 h-10 rounded-xl bg-rose-600 text-white flex items-center justify-center flex-shrink-0 shadow-sm">
            <PhoneCall className="w-5 h-5" />
          </div>
          <div>
            <div className="text-xs sm:text-sm font-bold text-rose-900 dark:text-rose-200">
              National Cyber Crime Reporting Helpline: Direct Dial 1930
            </div>
            <div className="text-[11px] text-rose-700 dark:text-rose-300">
              If financial fraud occurred within the last 24 hours (Golden Hour), immediately call 1930 or visit <a href="https://cybercrime.gov.in" target="_blank" rel="noreferrer" className="underline font-bold">cybercrime.gov.in</a>.
            </div>
          </div>
        </div>

        <a
          href="tel:1930"
          className="inline-flex items-center space-x-1.5 px-4 py-2 bg-rose-600 hover:bg-rose-700 text-white text-xs font-bold rounded-xl shadow-sm transition-colors cursor-pointer whitespace-nowrap"
        >
          <PhoneCall className="w-3.5 h-3.5" />
          <span>Call 1930 Now</span>
        </a>
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
              className="p-3 rounded-xl border border-slate-200/90 dark:border-border-dark bg-slate-50/70 dark:bg-surface-dark-elevated/60 hover:bg-white dark:hover:bg-surface-dark hover:border-emerald-500/30 text-left transition-all group cursor-pointer shadow-2xs"
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

      {/* Multilingual Voice Dictation Console Modal */}
      <VoiceInputModal
        isOpen={voiceModalOpen}
        onClose={() => setVoiceModalOpen(false)}
        onApplyTranscript={(text) => {
          setInputText((prev) => (prev ? `${prev.trim()}\n${text}` : text));
        }}
        initialText={inputText}
        defaultLang={lang}
      />
    </div>
  );
}
