import React from 'react';
import { 
  GitFork, 
  Mail, 
  Globe, 
  KeyRound, 
  CreditCard, 
  ShieldAlert
} from 'lucide-react';

const STAGE_CONFIG = {
  lure: { label: 'Initial Lure / Engagement', icon: Mail, color: 'text-amber-600 dark:text-amber-400' },
  redirection: { label: 'Infrastructure / Fake Portal', icon: Globe, color: 'text-blue-600 dark:text-blue-400' },
  exploitation: { label: 'Credential / OTP Solicitation', icon: KeyRound, color: 'text-orange-600 dark:text-orange-400' },
  monetization: { label: 'Financial Loss / Unauthorized Debit', icon: CreditCard, color: 'text-red-600 dark:text-red-400' },
  execution: { label: 'Unauthorized Execution', icon: ShieldAlert, color: 'text-amber-600 dark:text-amber-400' },
};

export default function AttackPath({ attackPath, userState = 'received' }) {
  const structuredSteps = attackPath?.structured_steps || [];
  const rawSteps = attackPath?.steps || [];

  const reachedStageIndex = {
    received: 0,
    clicked: 1,
    entered_credentials: 2,
    paid: 3,
  }[userState] ?? 0;

  if ((!structuredSteps || structuredSteps.length === 0) && (!rawSteps || rawSteps.length === 0)) {
    return null;
  }

  return (
    <section className="clean-card clean-card-hover p-6" aria-label="Traceable Causal Attack Path">
      <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-200 dark:border-border-dark">
        <div className="flex items-center space-x-2.5">
          <GitFork className="w-5 h-5 text-accent dark:text-emerald-400" />
          <h3 className="text-base font-bold text-slate-900 dark:text-white">
            Traceable Causal Attack Path
          </h3>
        </div>
        <span className="text-[10px] font-mono px-2.5 py-0.5 rounded-full bg-slate-100 text-slate-700 dark:bg-surface-dark-hover dark:text-slate-300 border border-slate-200 dark:border-border-dark font-semibold">
          EVIDENCE-GROUNDED
        </span>
      </div>

      <p className="text-xs text-slate-600 dark:text-slate-400 mb-4 leading-relaxed">
        Sequential progression of how this attack operates from initial bait to potential exploitation. Solid cards indicate observed or reached stages; dashed cards represent projected downstream consequences.
      </p>

      {structuredSteps.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3 relative">
          {structuredSteps.map((step, idx) => {
            const stageKey = (step.causal_stage || 'lure').toLowerCase();
            const config = STAGE_CONFIG[stageKey] || STAGE_CONFIG.lure;
            const Icon = config.icon;
            const isReachedOrObserved = idx <= reachedStageIndex;

            return (
              <div key={idx} className="relative flex flex-col">
                <div
                  className={`flex-1 p-3.5 rounded-card border transition-all duration-200 flex flex-col justify-between ${
                    isReachedOrObserved
                      ? 'bg-slate-50 border-slate-300 shadow-sm ring-1 ring-amber-400/50 dark:bg-slate-950/90 dark:border-slate-700 dark:ring-amber-500/40'
                      : 'bg-white/50 dark:bg-slate-950/40 border-dashed border-slate-200 dark:border-slate-800 opacity-60'
                  }`}
                >
                  <div>
                    {/* Top Bar with Number & Icon */}
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center space-x-2">
                        <div className={`w-5 h-5 rounded-full flex items-center justify-center font-mono text-[10px] font-bold ${
                          isReachedOrObserved 
                            ? 'bg-amber-500 text-slate-950' 
                            : 'bg-slate-200 text-slate-600 dark:bg-slate-800 dark:text-slate-400'
                        }`}>
                          {idx + 1}
                        </div>
                        <Icon className={`w-4 h-4 ${config.color}`} />
                      </div>

                      {/* Reached Status Badge */}
                      <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded-badge ${
                        idx === reachedStageIndex 
                          ? 'bg-amber-100 text-amber-900 border border-amber-300 dark:bg-amber-950 dark:text-amber-300 dark:border-amber-600'
                          : isReachedOrObserved
                          ? 'bg-slate-200 text-slate-800 dark:bg-slate-800 dark:text-slate-300'
                          : 'bg-slate-100 text-slate-500 dark:bg-slate-900 dark:text-slate-600'
                      }`}>
                        {idx === reachedStageIndex ? 'CURRENT' : isReachedOrObserved ? 'REACHED' : 'POTENTIAL'}
                      </span>
                    </div>

                    {/* Stage Label */}
                    <h4 className="text-xs font-bold text-slate-900 dark:text-slate-200 mb-1">
                      {config.label}
                    </h4>

                    {/* Description */}
                    <p className="text-xs text-slate-700 dark:text-slate-400 leading-relaxed">
                      {step.description}
                    </p>
                  </div>

                  {/* Intended Consequence & Citations */}
                  <div className="mt-3 pt-2 border-t border-slate-200 dark:border-slate-800/80">
                    {step.intended_consequence && (
                      <div className="text-[11px] text-slate-600 dark:text-slate-400 mb-1.5 leading-snug">
                        <strong className="text-slate-800 dark:text-slate-200">Objective:</strong> {step.intended_consequence}
                      </div>
                    )}

                    {step.evidence_indices && step.evidence_indices.length > 0 && (
                      <div className="flex flex-wrap gap-1">
                        {step.evidence_indices.map((eIdx) => (
                          <span 
                            key={eIdx}
                            className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200 dark:bg-slate-800 dark:text-amber-300 dark:border-slate-700"
                          >
                            Evid. [{eIdx}]
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <div className="space-y-2">
          {rawSteps.map((step, idx) => (
            <div key={idx} className="flex items-start space-x-3 p-3 bg-slate-50 dark:bg-slate-950/60 rounded-btn border border-slate-200 dark:border-slate-800 text-xs sm:text-sm text-slate-800 dark:text-slate-300">
              <span className="w-5 h-5 rounded-full bg-slate-200 dark:bg-slate-800 flex items-center justify-center font-mono text-[10px] text-amber-600 dark:text-amber-400 font-bold flex-shrink-0 mt-0.5">
                {idx + 1}
              </span>
              <span className="leading-relaxed">{step}</span>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
