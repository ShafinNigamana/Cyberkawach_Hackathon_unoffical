import React, { useState } from 'react';
import { 
  BrainCircuit, 
  ChevronDown, 
  ChevronUp, 
  ShieldOff, 
  CheckCircle2, 
  Info,
  Layers
} from 'lucide-react';

export default function ExplanationCard({ explanation }) {
  const [detailsExpanded, setDetailsExpanded] = useState(false);

  if (!explanation) return null;

  const negativeBounds = explanation.what_cannot_be_concluded || [];
  const reasons = explanation.reasons || explanation.attack_vectors || [];
  const modelUsed = explanation.model || 'deterministic-fallback';

  // Two-line plain-language summary
  const summaryText = explanation.summary || 'Analytical assessment based on observed message artifacts and multi-layer fraud rules.';

  return (
    <section className="clean-card clean-card-hover p-5 sm:p-6" aria-label="Why We Concluded This Section">
      {/* Title Bar */}
      <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-200 dark:border-border-dark">
        <div className="flex items-center space-x-2.5">
          <BrainCircuit className="w-5 h-5 text-accent dark:text-emerald-400" />
          <h3 className="text-sm sm:text-base font-bold text-slate-900 dark:text-white">
            Why We Concluded This
          </h3>
        </div>
        <span className="text-[10px] font-mono px-2.5 py-0.5 rounded-full bg-slate-100 text-slate-600 dark:bg-surface-dark-hover dark:text-slate-300 border border-slate-200 dark:border-border-dark font-semibold">
          Engine: {modelUsed}
        </span>
      </div>

      {/* Two-Line Plain-Language Summary (Visible by Default, Scannable in < 2 Seconds) */}
      <p className="text-sm sm:text-base text-slate-800 dark:text-slate-200 font-medium leading-relaxed mb-3 line-clamp-2">
        {summaryText}
      </p>

      {/* Toggle Control: Show / Hide Details */}
      <div className="pt-1">
        <button
          type="button"
          onClick={() => setDetailsExpanded(!detailsExpanded)}
          aria-expanded={detailsExpanded}
          className="inline-flex items-center space-x-1.5 text-xs font-bold text-accent hover:text-emerald-700 dark:text-emerald-400 dark:hover:text-emerald-300 focus:outline-none transition-colors cursor-pointer"
        >
          <span>{detailsExpanded ? 'Hide technical breakdown' : 'Show forensic details & limits'}</span>
          {detailsExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </button>
      </div>

      {/* Expandable Forensic Breakdown */}
      {detailsExpanded && (
        <div className="mt-4 pt-4 border-t border-slate-200 dark:border-border-dark/80 space-y-4 text-xs">
          {/* Key Epistemic Factors (Checklist Style, Short Lines) */}
          {reasons.length > 0 && (
            <div>
              <h4 className="text-xs font-bold text-slate-900 dark:text-slate-300 uppercase tracking-wide mb-2 flex items-center space-x-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-amber-500 dark:bg-amber-400" />
                <span>Observed Decision Factors</span>
              </h4>
              <ul className="space-y-1.5">
                {reasons.map((reason, idx) => (
                  <li key={idx} className="flex items-start space-x-2 text-xs text-slate-700 dark:text-slate-300">
                    <CheckCircle2 className="w-3.5 h-3.5 text-amber-500 dark:text-amber-400 flex-shrink-0 mt-0.5" />
                    <span className="leading-relaxed">{reason}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Negative Bounds: What the Guardian Cannot Conclude */}
          {negativeBounds.length > 0 && (
            <div className="p-3.5 bg-slate-50 dark:bg-slate-950 rounded-btn border border-slate-200 dark:border-slate-800">
              <div className="flex items-center space-x-1.5 text-xs font-bold text-slate-900 dark:text-slate-300 mb-2">
                <ShieldOff className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400" />
                <span>What the Guardian Cannot Conclude:</span>
              </div>
              <ul className="space-y-1 text-slate-600 dark:text-slate-400">
                {negativeBounds.map((bound, idx) => (
                  <li key={idx} className="pl-3 border-l-2 border-slate-300 dark:border-slate-700 leading-relaxed">
                    {bound}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Uncertainty Assessment */}
          {explanation.uncertainty && (
            <div className="flex items-start space-x-2 text-xs text-slate-600 dark:text-slate-400 pt-2 border-t border-slate-200 dark:border-slate-800/80">
              <Info className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400 flex-shrink-0 mt-0.5" />
              <span>
                <strong className="text-slate-800 dark:text-slate-200">Uncertainty Bounds:</strong> {explanation.uncertainty}
              </span>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
