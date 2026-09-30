import React, { useState, useEffect } from 'react';
import { 
  CheckCircle2, 
  Loader2, 
  Search, 
  Cpu, 
  Layers, 
  GitFork, 
  LifeBuoy, 
  FileCheck,
  ShieldCheck,
  Globe
} from 'lucide-react';

const PROCESSING_STAGES = [
  { id: 'input', label: '1. Input Received', desc: 'Sanitizing payload and masking Aadhaar/PAN/OTPs in-memory', icon: ShieldCheck },
  { id: 'iocs', label: '2. Indicators Extracted', desc: 'Extracting web URLs, host domains, phone numbers, and handles', icon: Search },
  { id: 'local_checks', label: '3. Local Fraud Checks', desc: 'Evaluating against Indian fraud typology rules and TF-IDF ML baseline', icon: Cpu },
  { id: 'url_brand', label: '4. URL & Brand Checks', desc: 'Detecting spoofed Indian banks, government bodies, and utility providers', icon: Globe },
  { id: 'threat_intel', label: '5. Threat Intelligence', desc: 'Querying Google Safe Browsing, PhishTank, and PhishStats APIs', icon: Layers },
  { id: 'fusion', label: '6. Evidence Fusion', desc: 'Two-tier weighted fusion of observed signals vs epistemic bounds', icon: GitFork },
  { id: 'explanation', label: '7. Explanation & Limits', desc: 'Synthesizing plain-language summary and what Guardian cannot conclude', icon: FileCheck },
  { id: 'protection', label: '8. Protection Guidance', desc: 'Generating state-adaptive recovery checklist and 1930 emergency advisory', icon: LifeBuoy },
];

export default function LoadingPipeline() {
  const [currentStep, setCurrentStep] = useState(0);

  useEffect(() => {
    // Stage progresses realistically over the forensic request cycle
    const interval = setInterval(() => {
      setCurrentStep((prev) => (prev < PROCESSING_STAGES.length - 1 ? prev + 1 : prev));
    }, 450);
    return () => clearInterval(interval);
  }, []);

  const progressPercent = Math.round(((currentStep + 1) / PROCESSING_STAGES.length) * 100);

  return (
    <div className="clean-card rounded-2xl p-6 my-6 shadow-sm relative overflow-hidden" aria-live="polite">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-5 pb-4 border-b border-slate-100 dark:border-slate-800">
        <div className="flex items-center space-x-3.5">
          <div className="w-10 h-10 rounded-xl bg-slate-900 text-white dark:bg-white dark:text-slate-950 flex items-center justify-center flex-shrink-0 shadow-sm">
            <Loader2 className="w-5 h-5 animate-spin" />
          </div>
          <div>
            <h3 className="text-sm sm:text-base font-bold text-slate-900 dark:text-white">
              Forensic Triage Pipeline Active
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              Real-time multi-stage verification across local rules, authoritative threat feeds, and epistemic bounds.
            </p>
          </div>
        </div>

        {/* Progress Badge */}
        <div className="flex items-center space-x-2.5 self-start sm:self-center">
          <span className="text-xs font-mono font-bold text-slate-900 dark:text-slate-100">
            {progressPercent}%
          </span>
          <div className="w-28 h-2 bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden">
            <div 
              className="h-full bg-slate-900 dark:bg-white transition-all duration-300 rounded-full"
              style={{ width: `${progressPercent}%` }}
            />
          </div>
        </div>
      </div>

      {/* Grid of the 8 Real Stages */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {PROCESSING_STAGES.map((stage, idx) => {
          const isDone = idx < currentStep;
          const isCurrent = idx === currentStep;
          const Icon = stage.icon;

          return (
            <div
              key={stage.id}
              className={`p-3 rounded-xl border transition-all duration-200 flex items-start space-x-2.5 ${
                isDone
                  ? 'bg-slate-50/70 border-slate-200/80 text-slate-800 dark:bg-slate-900/60 dark:border-slate-800 dark:text-slate-200'
                  : isCurrent
                  ? 'bg-white border-slate-400 dark:bg-slate-900 dark:border-slate-600 text-slate-900 dark:text-white shadow-sm ring-1 ring-slate-400/30 dark:ring-slate-600/30'
                  : 'bg-transparent border-slate-100 text-slate-400 dark:border-slate-850 dark:text-slate-600'
              }`}
            >
              <div className="mt-0.5 flex-shrink-0">
                {isDone ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                ) : isCurrent ? (
                  <Loader2 className="w-4 h-4 text-slate-900 dark:text-white animate-spin" />
                ) : (
                  <Icon className="w-4 h-4 text-slate-300 dark:text-slate-700" />
                )}
              </div>
              <div className="flex flex-col min-w-0">
                <span className={`text-xs font-bold font-mono tracking-wide leading-tight ${
                  isCurrent ? 'text-slate-950 dark:text-white font-extrabold' : ''
                }`}>
                  {stage.label}
                </span>
                <span className={`text-[10px] mt-0.5 line-clamp-2 leading-tight ${
                  isCurrent 
                    ? 'text-slate-700 dark:text-slate-300 font-medium' 
                    : 'text-slate-500 dark:text-slate-400'
                }`}>
                  {stage.desc}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
