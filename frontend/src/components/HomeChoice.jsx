import React from 'react';
import { 
  MessageSquare, 
  Globe, 
  Camera, 
  ArrowRight, 
  ShieldCheck, 
  Lock, 
  PhoneCall, 
  FlaskConical, 
  Zap, 
  Building2, 
  QrCode, 
  PackageCheck, 
  Scale 
} from 'lucide-react';
import { PRESET_SCENARIOS } from '../data/presets';

export default function HomeChoice({ onSelectFlow, onSelectPreset }) {
  return (
    <div className="w-full max-w-4xl mx-auto space-y-8 py-4">
      {/* ─── Hero Heading & Single-Sentence Purpose ─── */}
      <div className="text-center space-y-3">
        <div className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-800 dark:text-slate-200 text-xs font-semibold">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          <span>National Citizen Cyber Threat Triage</span>
        </div>

        <h2 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-slate-900 dark:text-white">
          What do you want to check?
        </h2>

        <p className="text-sm sm:text-base text-slate-600 dark:text-slate-400 max-w-2xl mx-auto leading-relaxed">
          Cyber Fraud Guardian safely evaluates suspicious communications using passive forensic intelligence, protecting you without opening unsafe links or retaining your data.
        </p>
      </div>

      {/* ─── 3 Primary Task Selection Cards ─── */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Choice 1: Message / SMS */}
        <button
          type="button"
          onClick={() => onSelectFlow('message')}
          className="group text-left p-6 bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 hover:border-slate-400 dark:hover:border-slate-600 hover:shadow-md transition-all duration-200 cursor-pointer flex flex-col justify-between"
        >
          <div className="space-y-3">
            <div className="w-12 h-12 rounded-lg bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 flex items-center justify-center text-slate-800 dark:text-slate-200 group-hover:bg-slate-900 group-hover:text-white dark:group-hover:bg-slate-100 dark:group-hover:text-slate-900 transition-colors">
              <MessageSquare className="w-6 h-6" strokeWidth={1.8} />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-900 dark:text-white group-hover:text-slate-900 dark:group-hover:text-white">
                Message / SMS
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 leading-relaxed">
                Check suspicious text messages, WhatsApp forwards, bank alerts, electricity cutoff threats, or emails.
              </p>
            </div>
          </div>

          <div className="mt-6 pt-4 border-t border-slate-100 dark:border-slate-800/80 flex items-center justify-between text-xs font-semibold text-slate-800 dark:text-slate-200">
            <span>Analyze text message</span>
            <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
          </div>
        </button>

        {/* Choice 2: URL / Website */}
        <button
          type="button"
          onClick={() => onSelectFlow('url')}
          className="group text-left p-6 bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 hover:border-slate-400 dark:hover:border-slate-600 hover:shadow-md transition-all duration-200 cursor-pointer flex flex-col justify-between"
        >
          <div className="space-y-3">
            <div className="w-12 h-12 rounded-lg bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 flex items-center justify-center text-slate-800 dark:text-slate-200 group-hover:bg-slate-900 group-hover:text-white dark:group-hover:bg-slate-100 dark:group-hover:text-slate-900 transition-colors">
              <Globe className="w-6 h-6" strokeWidth={1.8} />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-900 dark:text-white group-hover:text-slate-900 dark:group-hover:text-white">
                URL / Website
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 leading-relaxed">
                Safely inspect a link or website without visiting it. Analyzes domain reputation, phishing feeds, and brand spoofing.
              </p>
            </div>
          </div>

          <div className="mt-6 pt-4 border-t border-slate-100 dark:border-slate-800/80 flex items-center justify-between text-xs font-semibold text-slate-800 dark:text-slate-200">
            <span>Inspect link safety</span>
            <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
          </div>
        </button>

        {/* Choice 3: Screenshot / Photo */}
        <button
          type="button"
          onClick={() => onSelectFlow('screenshot')}
          className="group text-left p-6 bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 hover:border-slate-400 dark:hover:border-slate-600 hover:shadow-md transition-all duration-200 cursor-pointer flex flex-col justify-between"
        >
          <div className="space-y-3">
            <div className="w-12 h-12 rounded-lg bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 flex items-center justify-center text-slate-800 dark:text-slate-200 group-hover:bg-slate-900 group-hover:text-white dark:group-hover:bg-slate-100 dark:group-hover:text-slate-900 transition-colors">
              <Camera className="w-6 h-6" strokeWidth={1.8} />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-900 dark:text-white group-hover:text-slate-900 dark:group-hover:text-white">
                Screenshot / Photo
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 leading-relaxed">
                Upload a screenshot or photo. Optical character recognition (OCR) extracts text and links for deep evaluation.
              </p>
            </div>
          </div>

          <div className="mt-6 pt-4 border-t border-slate-100 dark:border-slate-800/80 flex items-center justify-between text-xs font-semibold text-slate-800 dark:text-slate-200">
            <span>Upload screenshot</span>
            <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
          </div>
        </button>
      </div>

      {/* ─── Common Benchmark Typologies Quick-Test Bar ─── */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
          <div className="flex items-center space-x-1.5 text-xs font-bold text-slate-800 dark:text-slate-200">
            <FlaskConical className="w-3.5 h-3.5 text-slate-600 dark:text-slate-400" />
            <span>Or Quick-Test a Benchmark Scenario:</span>
          </div>
          <span className="text-[11px] text-slate-500 dark:text-slate-400">
            Preloaded real-world fraud cases
          </span>
        </div>

        <div className="flex flex-wrap gap-1.5">
          {PRESET_SCENARIOS.map((preset) => (
            <button
              key={preset.id}
              type="button"
              onClick={() => onSelectPreset(preset)}
              className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-md text-xs font-medium border border-slate-300 dark:border-slate-700 bg-slate-50 hover:bg-slate-100 dark:bg-slate-800/80 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-200 transition-colors cursor-pointer"
            >
              <span>{preset.title}</span>
            </button>
          ))}
        </div>
      </div>

      {/* ─── Institutional Trust & Guarantee Badges ─── */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2">
        <div className="flex items-center space-x-2.5 p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-white/60 dark:bg-slate-900/60 text-xs text-slate-600 dark:text-slate-400">
          <Lock className="w-4 h-4 text-slate-500 dark:text-slate-400 flex-shrink-0" />
          <span><strong>Zero Retention:</strong> Ephemeral in-memory analysis; zero storage.</span>
        </div>

        <div className="flex items-center space-x-2.5 p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-white/60 dark:bg-slate-900/60 text-xs text-slate-600 dark:text-slate-400">
          <ShieldCheck className="w-4 h-4 text-emerald-600 dark:text-emerald-500 flex-shrink-0" />
          <span><strong>Safe Sandbox:</strong> Unopened links tested via passive OSINT feeds.</span>
        </div>

        <div className="flex items-center space-x-2.5 p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-white/60 dark:bg-slate-900/60 text-xs text-slate-600 dark:text-slate-400">
          <PhoneCall className="w-4 h-4 text-red-600 dark:text-red-500 flex-shrink-0" />
          <span><strong>1930 Integration:</strong> Emergency Golden Hour guidance ready.</span>
        </div>
      </div>
    </div>
  );
}
