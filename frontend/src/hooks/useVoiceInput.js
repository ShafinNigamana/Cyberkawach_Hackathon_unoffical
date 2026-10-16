/**
 * useVoiceInput — Resilient dual-engine microphone and voice recognition hook.
 *
 * 1. Directly requests hardware microphone access via navigator.mediaDevices.getUserMedia.
 * 2. If the user allowed microphone permission, the mic ACTIVATES immediately (no false "voice denied").
 * 3. Runs native SpeechRecognition in parallel if permitted by the browser origin.
 * 4. If Web Speech is restricted (e.g. Chrome blocking speech cloud on http://127.0.0.1),
 *    the hardware microphone stays active, records the audio with MediaRecorder,
 *    and transcribes it via the backend /api/audio/transcribe endpoint.
 * 5. Provides a built-in simulation fallback (simulateVoiceSample) for quick testing.
 */

import { useState, useRef, useCallback, useEffect } from 'react';

const LANG_BCP47 = {
  en: 'en-IN',
  hi: 'hi-IN',
  gu: 'gu-IN',
  ta: 'ta-IN',
  te: 'te-IN',
  bn: 'bn-IN',
  mr: 'mr-IN',
  kn: 'kn-IN',
  ml: 'ml-IN',
  pa: 'pa-IN',
  ur: 'ur-IN',
  or: 'or-IN',
  as: 'as-IN',
};

const SAMPLE_TRANSCRIPTS = {
  hi: 'चेतावनी: आपका बिजली बिल 4,890 रुपये बकाया है। आज रात 9:30 बजे बिजली काट दी जाएगी। तुरंत इस लिंक पर क्लिक करके बिल भरें http://power-bijli-update.in/pay या लाइनमैन से संपर्क करें 9876543210',
  en: 'URGENT: Your SBI account access has been suspended due to pending KYC verification. Please click https://sbi-kyc-update.me/verify to update your Aadhaar card immediately.',
  ta: 'எச்சரிக்கை: உங்கள் மின் கட்டணம் நிலுவையில் உள்ளது. உடனடியாக இந்த இணைப்பை கிளிக் செய்யவும் http://tnebl-online.in/pay',
  te: 'హెచ్చరిక: మీ బ్యాంక్ ఖాతా నిలిపివేయబడింది. దయచేసి వెంటనే ధృవీకరించండి http://sbi-kyc-update.me',
  bn: 'জরুরি সতর্কতা: আপনার বিদ্যুৎ সংযোগ বিচ্ছিন্ন করা হবে। অবিলম্বে বিল পরিশোধ করুন http://bijli-pay.top',
};

export function useVoiceInput({ onTranscript, lang = 'en' }) {
  const [isListening, setIsListening] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [isSimulating, setIsSimulating] = useState(false);
  const [audioLevel, setAudioLevel] = useState(0);
  const [status, setStatus] = useState('idle'); // 'idle' | 'listening' | 'processing' | 'simulating' | 'error_permission' | 'error_unsupported' | 'error_generic'
  const [errorMessage, setErrorMessage] = useState('');

  const recognitionRef = useRef(null);
  const streamRef = useRef(null);
  const mediaRecorderRef = useRef(null);
  const audioChunksRef = useRef([]);
  const onTranscriptRef = useRef(onTranscript);
  const simulationTimerRef = useRef(null);
  const hasReceivedTranscriptRef = useRef(false);
  const audioContextRef = useRef(null);
  const animFrameRef = useRef(null);

  useEffect(() => {
    onTranscriptRef.current = onTranscript;
  }, [onTranscript]);

  const isSupported =
    typeof window !== 'undefined' &&
    !!(
      (window.navigator?.mediaDevices?.getUserMedia) ||
      window.SpeechRecognition ||
      window.webkitSpeechRecognition
    );

  // Stop everything safely
  const cleanupAudio = useCallback(() => {
    if (animFrameRef.current) {
      cancelAnimationFrame(animFrameRef.current);
      animFrameRef.current = null;
    }
    if (audioContextRef.current) {
      try {
        audioContextRef.current.close();
      } catch (_) {}
      audioContextRef.current = null;
    }
    if (mediaRecorderRef.current && mediaRecorderRef.current.state !== 'inactive') {
      try {
        mediaRecorderRef.current.stop();
      } catch (_) {}
    }
    if (streamRef.current) {
      streamRef.current.getTracks().forEach((t) => t.stop());
      streamRef.current = null;
    }
    if (recognitionRef.current) {
      try {
        recognitionRef.current.abort();
      } catch (_) {}
      recognitionRef.current = null;
    }
    setAudioLevel(0);
  }, []);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      cleanupAudio();
      if (simulationTimerRef.current) {
        clearInterval(simulationTimerRef.current);
      }
    };
  }, [cleanupAudio]);

  const stop = useCallback(async () => {
    if (simulationTimerRef.current) {
      clearInterval(simulationTimerRef.current);
      simulationTimerRef.current = null;
    }

    const hadRecognitionTranscript = hasReceivedTranscriptRef.current;
    const recordedChunks = [...audioChunksRef.current];

    cleanupAudio();
    setIsListening(false);
    setIsSimulating(false);

    // If browser speech recognition already produced text, we are finished!
    if (hadRecognitionTranscript) {
      setStatus('idle');
      return;
    }

    // If browser SpeechRecognition was blocked (e.g. 127.0.0.1 origin block in Chrome),
    // transcribe the recorded audio buffer via backend /api/audio/transcribe
    if (recordedChunks.length > 0) {
      setIsProcessing(true);
      setStatus('processing');
      try {
        const audioBlob = new Blob(recordedChunks, { type: 'audio/webm' });
        // Only transcribe if audio has reasonable size (> 2KB)
        if (audioBlob.size > 2048) {
          const formData = new FormData();
          formData.append('file', audioBlob, 'citizen_voice.webm');
          const targetLang = LANG_BCP47[lang] || 'hi-IN';

          const res = await fetch(`/api/audio/transcribe?lang=${encodeURIComponent(targetLang)}`, {
            method: 'POST',
            body: formData,
          });

          if (res.ok) {
            const data = await res.json();
            if (data.transcript && data.transcript.trim()) {
              onTranscriptRef.current(data.transcript.trim(), true);
              setStatus('idle');
              setIsProcessing(false);
              return;
            }
          }
        }
      } catch (err) {
        console.info('Backend audio transcription notice:', err);
      }
      setIsProcessing(false);
    }

    setStatus('idle');
  }, [cleanupAudio, lang]);

  const start = useCallback(async () => {
    setErrorMessage('');
    hasReceivedTranscriptRef.current = false;
    audioChunksRef.current = [];

    // 1. Direct hardware microphone activation via getUserMedia
    let stream = null;
    if (navigator?.mediaDevices?.getUserMedia) {
      try {
        stream = await navigator.mediaDevices.getUserMedia({ audio: true });
        streamRef.current = stream;
      } catch (err) {
        console.warn('Microphone getUserMedia error:', err);
        // Only set error_permission if user explicitly denied the hardware prompt
        if (err.name === 'NotAllowedError' || err.name === 'PermissionDeniedError') {
          setStatus('error_permission');
          setErrorMessage(
            'Microphone access blocked. Click the lock/tune icon in your address bar to Allow microphone, or open http://localhost:8000.'
          );
          setIsListening(false);
          return;
        }
      }
    }

    // 2. We have the microphone active! Activate listening state immediately!
    setIsListening(true);
    setStatus('listening');
    setErrorMessage('');

    // 3. Audio visualizer setup via AudioContext
    if (stream) {
      try {
        const AudioCtx = window.AudioContext || window.webkitAudioContext;
        if (AudioCtx) {
          const audioCtx = new AudioCtx();
          audioContextRef.current = audioCtx;
          const source = audioCtx.createMediaStreamSource(stream);
          const analyser = audioCtx.createAnalyser();
          analyser.fftSize = 64;
          source.connect(analyser);

          const dataArray = new Uint8Array(analyser.frequencyBinCount);
          const updateAudioLevel = () => {
            if (!streamRef.current) return;
            analyser.getByteFrequencyData(dataArray);
            let sum = 0;
            for (let i = 0; i < dataArray.length; i++) {
              sum += dataArray[i];
            }
            const avg = sum / dataArray.length;
            setAudioLevel(Math.min(100, Math.round((avg / 128) * 100)));
            animFrameRef.current = requestAnimationFrame(updateAudioLevel);
          };
          updateAudioLevel();
        }
      } catch (_) {}

      // 4. Record audio chunks in background via MediaRecorder
      try {
        if (typeof window.MediaRecorder !== 'undefined') {
          const recorder = new MediaRecorder(stream);
          mediaRecorderRef.current = recorder;
          recorder.ondataavailable = (e) => {
            if (e.data && e.data.size > 0) {
              audioChunksRef.current.push(e.data);
            }
          };
          recorder.start(250); // Slice every 250ms
        }
      } catch (_) {}
    }

    // 5. Concurrently initiate SpeechRecognition if available
    const SpeechRecognition =
      typeof window !== 'undefined'
        ? window.SpeechRecognition || window.webkitSpeechRecognition
        : null;

    if (SpeechRecognition) {
      try {
        if (recognitionRef.current) {
          try {
            recognitionRef.current.abort();
          } catch (_) {}
        }

        const recognition = new SpeechRecognition();
        recognition.lang = LANG_BCP47[lang] || 'en-IN';
        recognition.continuous = true;
        recognition.interimResults = true;
        recognition.maxAlternatives = 1;

        recognition.onresult = (event) => {
          for (let i = event.resultIndex; i < event.results.length; i++) {
            const result = event.results[i];
            const text = result[0].transcript;
            if (text && text.trim()) {
              hasReceivedTranscriptRef.current = true;
              onTranscriptRef.current(text, result.isFinal);
            }
          }
        };

        recognition.onerror = (event) => {
          // If browser throws 'not-allowed' or 'network' due to 127.0.0.1 IP origin,
          // DO NOT CANCEL THE RECORDING! The user has an active microphone and MediaRecorder!
          console.info('SpeechRecognition note:', event.error);
          if (event.error === 'not-allowed' && !stream) {
            setStatus('error_permission');
            setErrorMessage('Microphone blocked. Please grant permission in browser settings.');
            setIsListening(false);
          }
        };

        recognition.onend = () => {
          recognitionRef.current = null;
        };

        recognitionRef.current = recognition;
        recognition.start();
      } catch (err) {
        console.info('SpeechRecognition startup note:', err);
      }
    }
  }, [lang]);

  // Simulation fallback: streams a realistic emergency voice message word-by-word
  const simulateVoiceSample = useCallback(() => {
    cleanupAudio();
    setIsListening(true);
    setIsSimulating(true);
    setStatus('simulating');
    setErrorMessage('');

    const sampleText = SAMPLE_TRANSCRIPTS[lang] || SAMPLE_TRANSCRIPTS.hi;
    const words = sampleText.split(' ');
    let currentIdx = 0;
    let accumulated = words[0];

    onTranscriptRef.current(accumulated, words.length === 1);
    currentIdx = 1;

    simulationTimerRef.current = setInterval(() => {
      if (currentIdx < words.length) {
        accumulated += ` ${words[currentIdx]}`;
        currentIdx += 1;
        const isFinal = currentIdx >= words.length;
        onTranscriptRef.current(accumulated, isFinal);
        if (isFinal) {
          clearInterval(simulationTimerRef.current);
          simulationTimerRef.current = null;
          setIsSimulating(false);
          setIsListening(false);
          setStatus('idle');
        }
      } else {
        clearInterval(simulationTimerRef.current);
        simulationTimerRef.current = null;
        setIsSimulating(false);
        setIsListening(false);
        setStatus('idle');
      }
    }, 100);
  }, [cleanupAudio, lang]);

  const toggle = useCallback(() => {
    if (isListening || isSimulating) {
      stop();
    } else {
      start();
    }
  }, [isListening, isSimulating, start, stop]);

  return {
    isListening: isListening || isSimulating,
    isRealMicListening: isListening && !isSimulating,
    isProcessing,
    isSimulating,
    audioLevel,
    status,
    errorMessage,
    isSupported,
    toggle,
    stop,
    start,
    simulateVoiceSample,
  };
}
