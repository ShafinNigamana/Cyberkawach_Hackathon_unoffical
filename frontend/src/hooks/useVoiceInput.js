/**
 * useVoiceInput — Browser-local Web Speech API hook
 *
 * Uses the native SpeechRecognition API (no paid service, no audio sent to backend).
 * Fires onTranscript(text, isFinal) on every result event:
 *   isFinal=false  → interim (partial) result — fires continuously while you speak
 *   isFinal=true   → committed final result — fires when the engine locks a phrase
 *
 * Supported recognition language BCP-47 codes (Chrome / Edge):
 *   en → en-IN   hi → hi-IN   gu → gu-IN
 *   ta → ta-IN   te → te-IN   bn → bn-IN
 *
 * Falls back gracefully when SpeechRecognition is unavailable.
 */

import { useState, useRef, useCallback, useEffect } from 'react';

const LANG_BCP47 = {
  en: 'en-IN',
  hi: 'hi-IN',
  gu: 'gu-IN',
  ta: 'ta-IN',
  te: 'te-IN',
  bn: 'bn-IN',
};

/**
 * @param {object}   options
 * @param {function} options.onTranscript  (text: string, isFinal: boolean) => void
 * @param {string}   options.lang          App language code
 * @returns {{ isListening, status, isSupported, toggle, stop }}
 */
export function useVoiceInput({ onTranscript, lang = 'en' }) {
  const [isListening, setIsListening] = useState(false);
  const [status, setStatus]           = useState('idle');
  const recognitionRef                = useRef(null);
  const onTranscriptRef               = useRef(onTranscript);

  // Keep the callback ref fresh without recreating recognition on every render
  useEffect(() => { onTranscriptRef.current = onTranscript; }, [onTranscript]);

  const isSupported =
    typeof window !== 'undefined' &&
    !!(window.SpeechRecognition || window.webkitSpeechRecognition);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (recognitionRef.current) {
        try { recognitionRef.current.abort(); } catch (_) { /* ignore */ }
        recognitionRef.current = null;
      }
    };
  }, []);

  const stop = useCallback(() => {
    if (recognitionRef.current) {
      try { recognitionRef.current.stop(); } catch (_) { /* ignore */ }
    }
    setIsListening(false);
    setStatus('idle');
  }, []);

  const start = useCallback(() => {
    if (!isSupported) { setStatus('error_unsupported'); return; }

    const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
    const recognition       = new SpeechRecognition();

    recognition.lang            = LANG_BCP47[lang] || 'en-IN';
    recognition.continuous      = true;   // keep listening until user clicks stop
    recognition.interimResults  = true;   // fire partial results as user speaks
    recognition.maxAlternatives = 1;

    recognition.onstart = () => {
      setIsListening(true);
      setStatus('listening');
    };

    recognition.onresult = (event) => {
      // Walk only the NEW results added since the last event
      for (let i = event.resultIndex; i < event.results.length; i++) {
        const result = event.results[i];
        const text   = result[0].transcript;

        if (result.isFinal) {
          // Committed phrase — lock it in
          onTranscriptRef.current(text, true);
        } else {
          // Partial phrase — stream it live
          onTranscriptRef.current(text, false);
        }
      }
    };

    recognition.onerror = (event) => {
      switch (event.error) {
        case 'not-allowed':
        case 'service-not-allowed':
          setStatus('error_permission');   break;
        case 'no-speech':
          setStatus('error_no_speech');    break;
        case 'network':
          setStatus('error_network');      break;
        default:
          setStatus('error_generic');
      }
      setIsListening(false);
    };

    recognition.onend = () => {
      setIsListening(false);
      setStatus((prev) => (prev === 'listening' ? 'idle' : prev));
    };

    recognitionRef.current = recognition;
    try {
      recognition.start();
    } catch (_) {
      setStatus('error_generic');
      setIsListening(false);
    }
  }, [isSupported, lang]);   // Note: onTranscript intentionally excluded — we use the ref

  const toggle = useCallback(() => {
    if (isListening) { stop(); }
    else             { setStatus('idle'); start(); }
  }, [isListening, start, stop]);

  return { isListening, status, isSupported, toggle, stop };
}
