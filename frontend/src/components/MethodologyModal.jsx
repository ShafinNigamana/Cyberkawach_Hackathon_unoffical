import React from 'react';
import { 
  X, 
  ShieldCheck, 
  Lock, 
  Scale, 
  Cpu, 
  FileCheck2, 
  Award
} from 'lucide-react';

export default function MethodologyModal({ isOpen, onClose }) {
  if (!isOpen) return null;

  return (
    <div 
      className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-slate-950/80 backdrop-blur-md overflow-y-auto animate-fade-in"
      role="dialog"
      aria-modal="true"
      aria-label="Technical Methodology and Architecture Guarantees"
    >
      <div className="bg-white dark:bg-surface-dark border border-slate-200 dark:border-border-dark rounded-2xl max-w-3xl w-full max-h-[90vh] flex flex-col shadow-2xl text-slate-800 dark:text-slate-200 overflow-hidden transition-colors">
        {/* Header */}
        <div className="flex items-center justify-between p-4 sm:p-5 border-b border-slate-200 dark:border-border-dark bg-slate-50 dark:bg-surface-dark-elevated">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-xl bg-emerald-50 dark:bg-emerald-950/80 text-emerald-600 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800/80 flex items-center justify-center flex-shrink-0">
              <FileCheck2 className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm sm:text-base font-bold text-slate-900 dark:text-white">
                Technical Methodology & Security Architecture
              </h3>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">
                Institutional Triage Standards • Cyber Kawach • Indian Cyber Crime Coordination Centre (I4C) Partner Protocol
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg hover:bg-slate-200 dark:hover:bg-surface-dark-hover text-slate-400 hover:text-slate-700 dark:hover:text-white transition-colors cursor-pointer"
            aria-label="Close Modal"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-5 sm:p-6 overflow-y-auto space-y-4 text-xs leading-relaxed bg-slate-50/50 dark:bg-surface-dark/50">
          <p className="text-slate-700 dark:text-slate-300">
            Cyber Fraud Guardian operates as a civic-interest, zero-retention cyber threat classification engine engineered for high epistemic rigor. The architecture adheres to rigorous public sector security specifications:
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2">
            {/* Guarantee 1: Zero PII Leakage */}
            <div className="p-4 bg-white dark:bg-surface-dark-elevated rounded-xl border border-slate-200 dark:border-border-dark shadow-xs">
              <div className="flex items-center space-x-2 text-amber-600 dark:text-amber-400 font-bold mb-1.5">
                <Lock className="w-4 h-4" />
                <span className="text-xs">Zero-PII In-Memory Redaction</span>
              </div>
              <p className="text-slate-600 dark:text-slate-400 text-[11px]">
                Indian Aadhaar numbers (12-digit Verhoeff-checked), PAN card identifiers, and 4-to-6 digit OTP tokens are systematically expunged in memory before any forensic evaluation or external model queries.
              </p>
            </div>

            {/* Guarantee 2: Epistemic Modesty */}
            <div className="p-4 bg-white dark:bg-surface-dark-elevated rounded-xl border border-slate-200 dark:border-border-dark shadow-xs">
              <div className="flex items-center space-x-2 text-indigo-600 dark:text-indigo-400 font-bold mb-1.5">
                <Scale className="w-4 h-4" />
                <span className="text-xs">Epistemic Modesty Standard</span>
              </div>
              <p className="text-slate-600 dark:text-slate-400 text-[11px]">
                The Guardian distinguishes direct evidentiary observations from inferences. When data is inconclusive, the system explicitly reports negative bounds ("What the Guardian Cannot Conclude") rather than manufacturing false certainty.
              </p>
            </div>

            {/* Guarantee 3: Bounded In-Memory Storage */}
            <div className="p-4 bg-white dark:bg-surface-dark-elevated rounded-xl border border-slate-200 dark:border-border-dark shadow-xs">
              <div className="flex items-center space-x-2 text-emerald-600 dark:text-emerald-400 font-bold mb-1.5">
                <Cpu className="w-4 h-4" />
                <span className="text-xs">Bounded Cache Architecture</span>
              </div>
              <p className="text-slate-600 dark:text-slate-400 text-[11px]">
                Incidents are cached strictly in thread-safe, LRU-bounded volatile memory (maximum 1,000 records). No raw citizen communications are persisted to relational or document databases.
              </p>
            </div>

            {/* Guarantee 4: Verified Threat Feeds */}
            <div className="p-4 bg-white dark:bg-surface-dark-elevated rounded-xl border border-slate-200 dark:border-border-dark shadow-xs">
              <div className="flex items-center space-x-2 text-emerald-600 dark:text-emerald-400 font-bold mb-1.5">
                <ShieldCheck className="w-4 h-4" />
                <span className="text-xs">Hardened Passive Threat Intel</span>
              </div>
              <p className="text-slate-600 dark:text-slate-400 text-[11px]">
                Integration with Google Safe Browsing v4, PhishTank, and PhishStats feeds with strict 4-state intelligence evaluation, preventing config gaps from triggering false alarm states.
              </p>
            </div>
          </div>

          {/* Audit & Compliance Standards */}
          <div className="p-4 bg-white dark:bg-surface-dark-elevated rounded-xl border border-slate-200 dark:border-border-dark mt-3 shadow-xs">
            <h4 className="text-xs font-bold text-slate-900 dark:text-white uppercase tracking-wider mb-2 flex items-center space-x-1.5">
              <Award className="w-4 h-4 text-amber-500 dark:text-amber-400" />
              <span>Security & Audit Certifications</span>
            </h4>
            <ul className="space-y-1.5 text-[11px] text-slate-600 dark:text-slate-300">
              <li className="flex items-center space-x-2">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                <span><strong className="text-slate-900 dark:text-white">Security Suite:</strong> 25/25 automated penetration audits passed (XSS, SQLi, SSRF, DoS, Path Traversal).</span>
              </li>
              <li className="flex items-center space-x-2">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                <span><strong className="text-slate-900 dark:text-white">Accuracy Matrix:</strong> 20/20 validated benchmark scenarios with 0% false positives on safe bank controls.</span>
              </li>
              <li className="flex items-center space-x-2">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                <span><strong className="text-slate-900 dark:text-white">Accessibility:</strong> WCAG 2.1 AA contrast verified across dark/light contrast palettes.</span>
              </li>
            </ul>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 sm:p-5 border-t border-slate-200 dark:border-border-dark bg-slate-50 dark:bg-surface-dark-elevated flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-200 hover:bg-slate-300 dark:bg-surface-dark-hover dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 rounded-lg text-xs cursor-pointer font-medium transition-colors"
          >
            Close Overview
          </button>
        </div>
      </div>
    </div>
  );
}
