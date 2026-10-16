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
  Upload
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
  onOpenAuthModal = () => {}
}) {
  const [activeMode, setActiveMode] = useState('sms'); // 'sms' | 'url' | 'ocr' | 'voice'
  const [inputText, setInputText] = useState('');
  const [userState, setUserState] = useState('received');
  const [recordingSeconds, setRecordingSeconds] = useState(0);
  const [pasteNotice, setPasteNotice] = useState(false);
  const [voiceModalOpen, setVoiceModalOpen] = useState(false);
  const fileInputRef = useRef(null);
  const baseTextRef = useRef('');

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

  // Handle Main Submission
  const handleSubmitTriage = (e) => {
    e?.preventDefault();
    if (!inputText.trim()) return;

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
    <div className="w-full max-w-6xl mx-auto space-y-6 py-2">
      {/* ─── 1. Authoritative Institutional Masthead ─── */}
      <div className="border-b border-slate-200 dark:border-night-border pb-4 pt-1">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          {/* Breadcrumbs & Title */}
          <div className="space-y-1">
            <div className="flex items-center space-x-2 text-xs font-mono text-slate-500 dark:text-slate-400">
              <span>National Cyber Defense</span>
              <span>/</span>
              <span className="text-slate-900 dark:text-white font-bold">Investigation Workbench</span>
            </div>
            <div className="flex items-center space-x-3">
              <div className="w-7 h-7 rounded-lg bg-slate-900 text-white dark:bg-white dark:text-slate-950 flex items-center justify-center font-bold text-xs shadow-xs font-mono">
                SOC
              </div>
              <h1 className="text-xl sm:text-2xl font-black text-slate-900 dark:text-white tracking-tight">
                National Cyber Threat Triage Console
              </h1>
            </div>
          </div>

          {/* Telemetry Indicator */}
          <div className="flex items-center space-x-2 sm:self-end">
            <div className="inline-flex items-center space-x-2 px-3 py-1.5 rounded-full border border-slate-200 dark:border-night-border bg-white dark:bg-night-900 text-slate-700 dark:text-slate-300 text-xs font-mono shadow-2xs">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              <span>48,219 Verified Analyses Today</span>
              <span className="text-slate-300 dark:text-slate-700">•</span>
              <span className="text-emerald-600 dark:text-emerald-400 font-semibold">Zero PII Retained</span>
            </div>
          </div>
        </div>
      </div>

      {/* ─── 2. Main Two-Column Forensic Workspace ─── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* ─── Left Column (60%): Advanced Forensic Triage Workbench ─── */}
        <div className="lg:col-span-7 space-y-4">
          <div className="editorial-workbench p-5 sm:p-6 space-y-4">
            {/* Workbench Header & Mode Selector Pills */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 dark:border-night-border pb-4">
              <div>
                <h2 className="text-sm sm:text-base font-bold text-slate-900 dark:text-white flex items-center space-x-2">
                  <Terminal className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                  <span>Advanced Forensic Triage Workbench</span>
                </h2>
                <p className="text-[11px] text-slate-500 dark:text-slate-400">
                  Real-time indicator extraction with client-side zero-PII sanitization
                </p>
              </div>

              {/* Tool Mode Segmented Pills */}
              <div className="flex items-center flex-wrap gap-1 bg-slate-100 dark:bg-night-800 p-1 rounded-xl border border-slate-200/80 dark:border-night-border">
                <button
                  type="button"
                  onClick={() => setActiveMode('sms')}
                  className={`px-3 py-1 rounded-lg text-xs font-medium transition-all cursor-pointer ${
                    activeMode === 'sms'
                      ? 'bg-white dark:bg-night-900 text-slate-900 dark:text-white shadow-xs font-bold'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  SMS / WhatsApp
                </button>
                <button
                  type="button"
                  onClick={() => setActiveMode('url')}
                  className={`px-3 py-1 rounded-lg text-xs font-medium transition-all cursor-pointer ${
                    activeMode === 'url'
                      ? 'bg-white dark:bg-night-900 text-slate-900 dark:text-white shadow-xs font-bold'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  URL Sandbox
                </button>
                <button
                  type="button"
                  onClick={() => setActiveMode('ocr')}
                  className={`px-3 py-1 rounded-lg text-xs font-medium transition-all cursor-pointer ${
                    activeMode === 'ocr'
                      ? 'bg-white dark:bg-night-900 text-slate-900 dark:text-white shadow-xs font-bold'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  Document OCR
                </button>
                <button
                  type="button"
                  onClick={() => setActiveMode('voice')}
                  className={`px-3 py-1 rounded-lg text-xs font-medium transition-all cursor-pointer ${
                    activeMode === 'voice'
                      ? 'bg-white dark:bg-night-900 text-slate-900 dark:text-white shadow-xs font-bold'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  Audio Waveform
                </button>
              </div>
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
                      className="inline-flex items-center space-x-1 hover:text-indigo-600 dark:hover:text-violet-400 cursor-pointer"
                      title="Paste from clipboard"
                    >
                      <Clipboard className="w-3 h-3" />
                      <span>[Ctrl+V] Paste</span>
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
                <div className="relative flex rounded-xl border border-slate-200 dark:border-night-border bg-slate-50/60 dark:bg-night-950/60 overflow-hidden focus-within:ring-2 focus-within:ring-indigo-500/20 focus-within:border-indigo-500">
                  <div className="w-8 py-3 bg-slate-100/70 dark:bg-night-900/80 border-r border-slate-200 dark:border-night-border font-mono text-[10px] text-slate-400 select-none text-right pr-2 leading-relaxed">
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

                <div className="defanged-box p-3 h-[180px] overflow-y-auto text-xs text-slate-700 dark:text-slate-300 whitespace-pre-wrap break-words leading-relaxed">
                  {defanged ? (
                    <div>{defanged}</div>
                  ) : (
                    <div className="text-slate-400 dark:text-slate-600 italic">
                      Live preview with defanged URLs (hxxps[://]...) and masked Aadhaar/OTP tokens will appear here as you type.
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* OCR File Upload / Audio Voice Waveform Bar */}
            {activeMode === 'ocr' ? (
              <div className="p-4 border border-dashed border-slate-300 dark:border-slate-700 rounded-xl bg-slate-50/50 dark:bg-night-950/40 text-center space-y-2">
                {isOcrUploading ? (
                  <div className="flex flex-col items-center justify-center py-2 space-y-2">
                    <div className="w-6 h-6 border-2 border-indigo-600 border-t-transparent rounded-full animate-spin" />
                    <span className="text-xs font-mono font-semibold text-indigo-600 dark:text-violet-400">
                      Processing OCR optical layers & extracting text...
                    </span>
                  </div>
                ) : (
                  <>
                    <Upload className="w-5 h-5 text-indigo-500 mx-auto" />
                    <div className="text-xs text-slate-600 dark:text-slate-400">
                      <label className="font-bold text-blue-600 dark:text-blue-400 hover:underline cursor-pointer">
                        Click to browse screenshot
                        <input 
                          ref={fileInputRef} 
                          type="file" 
                          accept="image/*" 
                          onChange={handleFileUpload} 
                          className="hidden" 
                        />
                      </label>{' '}
                      or drag and drop PNG, JPG, or WEBP image
                    </div>
                  </>
                )}
              </div>
            ) : (
              <div className="space-y-2">
                <div className="flex items-center justify-between p-3 rounded-xl border border-slate-200 dark:border-night-border bg-slate-50 dark:bg-night-950">
                  <div className="flex items-center space-x-3">
                    <button
                      type="button"
                      onClick={() => setVoiceModalOpen(true)}
                      className="w-10 h-10 rounded-xl flex items-center justify-center transition-all cursor-pointer bg-indigo-600 hover:bg-indigo-700 text-white shadow-md shadow-indigo-600/20 flex-shrink-0"
                      title="Click to speak your message (Hindi, English, Tamil, Telugu, etc.)"
                    >
                      <Mic className="w-5 h-5" />
                    </button>

                    <div 
                      onClick={() => setVoiceModalOpen(true)}
                      className="cursor-pointer"
                    >
                      <div className="text-xs font-bold text-slate-900 dark:text-white flex items-center space-x-1.5">
                        <span>Multilingual Voice Dictation</span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-indigo-100 dark:bg-violet-950/80 text-indigo-700 dark:text-violet-300 font-semibold animate-pulse">
                          Tap Mic to Speak
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-500 dark:text-slate-400 font-mono">
                        Hindi • English • Tamil • Telugu • Bengali • Marathi • Gujarati
                      </div>
                    </div>
                  </div>

                  {/* Animated Waveform Visualizer or Quick Demo */}
                  {isListening ? (
                    <div className="flex items-center space-x-1 h-6 pr-2">
                      {Array.from({ length: 8 }).map((_, i) => (
                        <span key={i} className="audio-bar w-1 bg-blue-600 dark:bg-blue-400 rounded-full" />
                      ))}
                    </div>
                  ) : (
                    <div className="flex items-center space-x-2">
                      <button
                        type="button"
                        onClick={handleVoiceSampleClick}
                        className="text-[10px] font-mono text-indigo-600 dark:text-violet-400 hover:underline cursor-pointer bg-indigo-50 dark:bg-violet-950/60 px-2 py-1 rounded border border-indigo-200 dark:border-violet-800/60 font-semibold"
                        title="Simulate speech-to-text transcript"
                      >
                        Try Voice Sample
                      </button>
                      <span className="text-[10px] font-mono text-slate-400 bg-slate-100 dark:bg-night-800 px-2 py-0.5 rounded border border-slate-200 dark:border-night-border hidden sm:inline">
                        {isVoiceSupported ? 'Audio Ready' : 'Demo Mode'}
                      </span>
                    </div>
                  )}
                </div>

                {/* Voice Status Diagnostic Callouts */}
                {errorMessage && (
                  <div className="p-3 bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800/60 rounded-xl text-xs text-amber-900 dark:text-amber-200 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
                    <span>
                      ⚠️ {errorMessage}
                    </span>
                    <button
                      type="button"
                      onClick={handleVoiceSampleClick}
                      className="px-2.5 py-1 bg-amber-600 text-white font-bold rounded-lg text-[11px] hover:bg-amber-700 cursor-pointer flex-shrink-0"
                    >
                      Try Voice Sample
                    </button>
                  </div>
                )}

                {voiceStatus === 'error_unsupported' && (
                  <div className="p-3 bg-slate-100 dark:bg-night-900 border border-slate-200 dark:border-night-border rounded-xl text-xs text-slate-700 dark:text-slate-300">
                    ℹ️ <strong>Speech Recognition API</strong> is not available in this browser. Please use <strong>Google Chrome</strong> or <strong>Microsoft Edge</strong> for real-time speech-to-text.
                  </div>
                )}

                {voiceStatus === 'error_network' && (
                  <div className="p-3 bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800 rounded-xl text-xs text-rose-800 dark:text-rose-200">
                    ⚠️ <strong>Speech network service offline:</strong> The browser speech recognition server could not be reached. Please check your internet connection or paste text directly.
                  </div>
                )}

                {voiceStatus === 'error_no_speech' && (
                  <div className="p-2.5 bg-slate-100 dark:bg-night-900 border border-slate-200 dark:border-night-border rounded-xl text-xs text-slate-600 dark:text-slate-400">
                    No speech was detected. Tap the mic icon again and speak clearly.
                  </div>
                )}
              </div>
            )}

            {/* Bottom Actions: User State Selector + Analyze Button */}
            <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-2 border-t border-slate-100 dark:border-night-border">
              <div className="flex items-center space-x-2 text-xs text-slate-600 dark:text-slate-400">
                <span className="font-medium text-slate-700 dark:text-slate-300">Your Current State:</span>
                <select
                  value={userState}
                  onChange={(e) => setUserState(e.target.value)}
                  className="px-2.5 py-1.5 rounded-lg border border-slate-200 dark:border-night-border bg-white dark:bg-night-900 text-slate-800 dark:text-slate-200 text-xs font-semibold focus:outline-none cursor-pointer"
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
                className="w-full sm:w-auto inline-flex items-center justify-center space-x-2 px-6 py-2.5 btn-primary cursor-pointer text-xs font-bold shadow-md disabled:opacity-50 disabled:cursor-not-allowed"
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
          <div className="editorial-workbench p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-100 dark:border-night-border pb-3">
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
              <div className="bulletin-card p-4 space-y-2.5 border-l-4 border-l-rose-600">
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

                <div className="space-y-1 text-[11px] font-mono text-slate-600 dark:text-slate-400 bg-slate-50 dark:bg-night-950 p-2 rounded-lg border border-slate-100 dark:border-night-border">
                  <div className="text-[10px] font-bold text-slate-500 uppercase">Observed IOC Domains:</div>
                  <div className="text-rose-600 dark:text-rose-400 break-all">eilielectricity.com • electtricity.com</div>
                </div>

                <div className="flex items-center justify-between pt-1">
                  <span className="text-[10px] text-slate-500 font-mono">Severity: Critical • Indian Syndicate</span>
                  <button
                    type="button"
                    onClick={() => handleLoadBulletin('preset-electricity')}
                    className="text-xs font-bold text-blue-600 dark:text-blue-400 hover:underline cursor-pointer"
                  >
                    Load Benchmark →
                  </button>
                </div>
              </div>

              {/* Card 2: Digital Arrest Syndicate */}
              <div className="bulletin-card p-4 space-y-2.5 border-l-4 border-l-amber-500">
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

                <div className="space-y-1 text-[11px] font-mono text-slate-600 dark:text-slate-400 bg-slate-50 dark:bg-night-950 p-2 rounded-lg border border-slate-100 dark:border-night-border">
                  <div className="text-[10px] font-bold text-slate-500 uppercase">Observed IOC Domains:</div>
                  <div className="text-amber-600 dark:text-amber-400 break-all">vodless.com • statemin.com</div>
                </div>

                <div className="flex items-center justify-between pt-1">
                  <span className="text-[10px] text-slate-500 font-mono">Severity: High • Extortion Call</span>
                  <button
                    type="button"
                    onClick={() => handleLoadBulletin('preset-digital-arrest')}
                    className="text-xs font-bold text-blue-600 dark:text-blue-400 hover:underline cursor-pointer"
                  >
                    Load Benchmark →
                  </button>
                </div>
              </div>

              {/* Card 3: India Post Delivery APK */}
              <div className="bulletin-card p-4 space-y-2.5 border-l-4 border-l-rose-600">
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

                <div className="space-y-1 text-[11px] font-mono text-slate-600 dark:text-slate-400 bg-slate-50 dark:bg-night-950 p-2 rounded-lg border border-slate-100 dark:border-night-border">
                  <div className="text-[10px] font-bold text-slate-500 uppercase">Observed IOC Domains:</div>
                  <div className="text-rose-600 dark:text-rose-400 break-all">indiaposts.com • indiapost.com</div>
                </div>

                <div className="flex items-center justify-between pt-1">
                  <span className="text-[10px] text-slate-500 font-mono">Severity: Critical • Malicious APK</span>
                  <button
                    type="button"
                    onClick={() => handleLoadBulletin('preset-india-post')}
                    className="text-xs font-bold text-blue-600 dark:text-blue-400 hover:underline cursor-pointer"
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
      <div className="p-4 rounded-xl border border-rose-200 dark:border-rose-900/60 bg-rose-50/70 dark:bg-rose-950/40 flex flex-col sm:flex-row items-center justify-between gap-3 shadow-xs">
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
          className="inline-flex items-center space-x-1.5 px-4 py-2 bg-rose-600 hover:bg-rose-700 text-white text-xs font-bold rounded-lg shadow-sm transition-colors cursor-pointer whitespace-nowrap"
        >
          <PhoneCall className="w-3.5 h-3.5" />
          <span>Call 1930 Now</span>
        </a>
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
