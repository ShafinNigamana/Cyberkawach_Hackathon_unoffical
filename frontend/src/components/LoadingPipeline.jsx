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

  return (
    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 my-6 shadow-xs" aria-live="polite">
      <div className="flex items-center space-x-3 mb-4 pb-3 border-b border-slate-100 dark:border-slate-800">
        <Loader2 className="w-5 h-5 text-slate-900 dark:text-slate-100 animate-spin" />
        <div>
          <h3 className="text-sm font-bold text-slate-900 dark:text-white">
            Executing Multi-Stage Forensic Triage Pipeline
          </h3>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Real-time execution across 11 verification modules, external intelligence feeds, and epistemic reasoning engines.
          </p>
        </div>
      </div>

      {/* Grid of the 8 Real Stages */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
        {PROCESSING_STAGES.map((stage, idx) => {
          const isDone = idx < currentStep;
          const isCurrent = idx === currentStep;
          const Icon = stage.icon;

          return (
            <div
              key={stage.id}
              className={`p-2.5 rounded-lg border transition-all duration-150 flex items-start space-x-2.5 ${
                isDone
                  ? 'bg-slate-50 border-slate-200 text-slate-800 dark:bg-slate-950 dark:border-slate-800 dark:text-slate-200'
                  : isCurrent
                  ? 'bg-slate-900 border-slate-900 text-white shadow-xs dark:bg-slate-800 dark:border-slate-700'
                  : 'bg-white border-slate-100 text-slate-400 dark:bg-slate-900/40 dark:border-slate-800/60 dark:text-slate-600'
              }`}
            >
              <div className="mt-0.5 flex-shrink-0">
                {isDone ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                ) : isCurrent ? (
                  <Loader2 className="w-4 h-4 text-white animate-spin" />
                ) : (
                  <Icon className="w-4 h-4 text-slate-300 dark:text-slate-700" />
                )}
              </div>
              <div className="flex flex-col min-w-0">
                <span className="text-xs font-bold font-mono tracking-wide leading-tight">
                  {stage.label}
                </span>
                <span className={`text-[10px] mt-0.5 line-clamp-2 leading-tight ${isCurrent ? 'text-slate-300' : 'text-slate-500 dark:text-slate-400'}`}>
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
