import React, { useState, useEffect, useRef } from 'react';
import { Mic, MicOff, Volume2, Sparkles, X, Check, Globe, RefreshCw, AlertCircle } from 'lucide-react';
import { useVoiceInput } from '../hooks/useVoiceInput';

const LANGUAGES = [
  { code: 'hi', label: 'हिंदी (Hindi)', bcp: 'hi-IN' },
  { code: 'en', label: 'English (India)', bcp: 'en-IN' },
  { code: 'ta', label: 'தமிழ் (Tamil)', bcp: 'ta-IN' },
  { code: 'te', label: 'తెలుగు (Telugu)', bcp: 'te-IN' },
  { code: 'bn', label: 'বাংলা (Bengali)', bcp: 'bn-IN' },
  { code: 'gu', label: 'ગુજરાતી (Gujarati)', bcp: 'gu-IN' },
  { code: 'mr', label: 'मराठी (Marathi)', bcp: 'mr-IN' },
];

export default function VoiceInputModal({
  isOpen,
  onClose,
  onApplyTranscript,
  initialText = '',
  defaultLang = 'hi',
}) {
  const [selectedLang, setSelectedLang] = useState(defaultLang);
  const [liveTranscript, setLiveTranscript] = useState('');
  const [recordingSeconds, setRecordingSeconds] = useState(0);

  const handleTranscript = (text, isFinal) => {
    setLiveTranscript(text);
  };

  const {
    isListening,
    isSimulating,
    status: voiceStatus,
    errorMessage,
    audioLevel,
    isSupported,
    start,
    stop,
    simulateVoiceSample,
  } = useVoiceInput({
    onTranscript: handleTranscript,
    lang: selectedLang,
  });

  // When modal opens, auto-start listening
  useEffect(() => {
    if (isOpen) {
      setLiveTranscript(initialText);
      setRecordingSeconds(0);
      start();
    } else {
      stop();
    }
  }, [isOpen]);

  // Recording timer
  useEffect(() => {
    let timer;
    if (isListening) {
      timer = setInterval(() => {
        setRecordingSeconds((prev) => prev + 1);
      }, 1000);
    } else {
      setRecordingSeconds(0);
    }
    return () => clearInterval(timer);
  }, [isListening]);

  if (!isOpen) return null;

  const handleDone = () => {
    stop();
    if (liveTranscript.trim()) {
      onApplyTranscript(liveTranscript.trim());
    }
    onClose();
  };

  const handleClose = () => {
    stop();
    onClose();
  };

  const isLocalhostIssue =
    typeof window !== 'undefined' &&
    window.location.hostname === '127.0.0.1' &&
    voiceStatus === 'error_permission';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/70 backdrop-blur-sm animate-fade-in">
      <div className="w-full max-w-lg bg-white dark:bg-night-900 border border-slate-200 dark:border-night-border rounded-2xl shadow-2xl overflow-hidden flex flex-col">
        {/* Modal Header */}
        <div className="p-4 sm:p-5 border-b border-slate-100 dark:border-night-border flex items-center justify-between bg-slate-50/60 dark:bg-night-950/60">
          <div className="flex items-center space-x-2.5">
            <div className={`w-8 h-8 rounded-xl flex items-center justify-center ${
              isListening ? 'bg-rose-600 text-white animate-pulse' : 'bg-indigo-600 text-white'
            }`}>
              <Mic className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm sm:text-base font-bold text-slate-900 dark:text-white">
                Multilingual Voice Dictation
              </h3>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">
                Speak suspicious call, SMS, or scam message in your regional language
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={handleClose}
            className="p-1 rounded-lg text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-night-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-5 sm:p-6 space-y-5">
          {/* Language Selector Bar */}
          <div className="space-y-1.5">
            <label className="text-[11px] font-bold text-slate-600 dark:text-slate-300 flex items-center space-x-1">
              <Globe className="w-3.5 h-3.5 text-indigo-500" />
              <span>Select Spoken Language:</span>
            </label>
            <div className="flex flex-wrap gap-1.5">
              {LANGUAGES.map((l) => (
                <button
                  key={l.code}
                  type="button"
                  onClick={() => {
                    setSelectedLang(l.code);
                    if (isListening) {
                      stop();
                      setTimeout(() => start(), 100);
                    }
                  }}
                  className={`px-2.5 py-1 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                    selectedLang === l.code
                      ? 'bg-indigo-600 text-white shadow-xs'
                      : 'bg-slate-100 dark:bg-night-800 text-slate-700 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-night-700'
                  }`}
                >
                  {l.label}
                </button>
              ))}
            </div>
          </div>

          {/* Central Pulsing Mic & Visualizer Area */}
          <div className="flex flex-col items-center justify-center p-6 rounded-2xl bg-slate-50 dark:bg-night-950/80 border border-slate-200 dark:border-night-border space-y-3">
            <div className="relative">
              {isListening && (
                <span className="absolute -inset-3 rounded-full bg-rose-500/20 animate-ping" />
              )}
              <button
                type="button"
                onClick={() => (isListening ? stop() : start())}
                className={`relative w-16 h-16 rounded-full flex items-center justify-center transition-all shadow-lg cursor-pointer ${
                  isListening
                    ? 'bg-rose-600 text-white ring-4 ring-rose-500/30'
                    : 'bg-slate-200 dark:bg-night-800 text-slate-700 dark:text-slate-300 hover:bg-slate-300'
                }`}
                title={isListening ? 'Click to stop listening' : 'Click to start microphone'}
              >
                {isListening ? (
                  <MicOff className="w-7 h-7" />
                ) : (
                  <Mic className="w-7 h-7 text-indigo-600 dark:text-violet-400" />
                )}
              </button>
            </div>

            {/* Status & Timer Indicator */}
            <div className="text-center space-y-1">
              <div className="text-xs font-bold text-slate-900 dark:text-white flex items-center justify-center space-x-1.5">
                {isListening ? (
                  <>
                    <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse" />
                    <span>Listening... Speak into microphone</span>
                  </>
                ) : (
                  <span>Microphone paused. Click to speak.</span>
                )}
              </div>
              <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
                {isListening ? `00:${recordingSeconds.toString().padStart(2, '0')}` : 'Ready'}
              </div>
            </div>

            {/* Soundwave Simulation Bars */}
            {isListening && (
              <div className="flex items-center space-x-1 h-5 pt-1">
                {Array.from({ length: 12 }).map((_, i) => (
                  <span
                    key={i}
                    className="w-1 bg-rose-500 rounded-full animate-pulse"
                    style={{
                      height: `${Math.max(6, (Math.sin(i * 0.8 + recordingSeconds * 2) * 0.5 + 0.5) * 20)}px`,
                      animationDelay: `${i * 0.08}s`,
                    }}
                  />
                ))}
              </div>
            )}
          </div>

          {/* Transcript Preview Box */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-xs font-bold text-slate-700 dark:text-slate-300">
              <span>Live Speech-to-Text Transcript:</span>
              {liveTranscript && (
                <button
                  type="button"
                  onClick={() => setLiveTranscript('')}
                  className="text-[11px] text-slate-400 hover:text-rose-500 cursor-pointer"
                >
                  Clear
                </button>
              )}
            </div>
            <textarea
              value={liveTranscript}
              onChange={(e) => setLiveTranscript(e.target.value)}
              placeholder="Your spoken words will appear here in real time. You can also edit this text before inserting..."
              rows={4}
              className="w-full p-3 rounded-xl border border-slate-200 dark:border-night-border bg-white dark:bg-night-900 text-slate-900 dark:text-white text-xs focus:ring-2 focus:ring-indigo-500/30 focus:outline-none resize-none font-sans leading-relaxed"
            />
          </div>

          {/* Notice & Localhost Resolver */}
          {isLocalhostIssue && (
            <div className="p-3 bg-amber-50 dark:bg-amber-950/50 border border-amber-200 dark:border-amber-800 rounded-xl text-xs text-amber-900 dark:text-amber-200 space-y-2">
              <div className="flex items-start space-x-2">
                <AlertCircle className="w-4 h-4 text-amber-600 flex-shrink-0 mt-0.5" />
                <p>
                  <strong>Chrome Security Requirement:</strong> Chrome blocks Web Speech on IP addresses like <code>127.0.0.1</code>, but allows it fully on <code>localhost</code>.
                </p>
              </div>
              <a
                href={window.location.href.replace('127.0.0.1', 'localhost')}
                className="inline-flex items-center space-x-1 font-bold text-indigo-700 dark:text-indigo-300 underline"
              >
                <span>Switch to http://localhost:8000 to enable native Chrome Speech</span>
              </a>
            </div>
          )}

          {errorMessage && !isLocalhostIssue && (
            <div className="p-3 bg-slate-100 dark:bg-night-800 border border-slate-200 dark:border-night-border rounded-xl text-xs text-slate-700 dark:text-slate-300 flex items-center justify-between">
              <span>{errorMessage}</span>
              <button
                type="button"
                onClick={() => start()}
                className="px-2 py-1 bg-indigo-600 text-white rounded font-bold text-[11px] cursor-pointer"
              >
                Retry
              </button>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-4 sm:p-5 border-t border-slate-100 dark:border-night-border bg-slate-50/60 dark:bg-night-950/60 flex flex-wrap items-center justify-between gap-3">
          <button
            type="button"
            onClick={simulateVoiceSample}
            className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg border border-indigo-200 dark:border-indigo-800 text-indigo-700 dark:text-indigo-300 text-xs font-semibold hover:bg-indigo-50 dark:hover:bg-indigo-950/50 cursor-pointer"
          >
            <Sparkles className="w-3.5 h-3.5 text-indigo-500" />
            <span>Try Voice Sample Demo</span>
          </button>

          <div className="flex items-center space-x-2">
            <button
              type="button"
              onClick={handleClose}
              className="px-3.5 py-1.5 rounded-lg text-xs font-semibold text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-night-800 cursor-pointer"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleDone}
              className="inline-flex items-center space-x-1.5 px-4 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-bold shadow-xs cursor-pointer"
            >
              <Check className="w-3.5 h-3.5" />
              <span>Insert Into Message</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
