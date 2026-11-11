import React from 'react';
import { 
  ShieldAlert, 
  PhoneCall, 
  AlertTriangle, 
  CheckCircle2, 
  RefreshCw,
  Clock,
  ExternalLink,
  ShieldCheck,
  ArrowRight
} from 'lucide-react';

export default function AdaptiveGuidance({ 
  response, 
  currentState, 
  onStateChange, 
  isUpdatingState,
  incidentId 
}) {
  if (!response) return null;

  const urgency = response.urgency || 'normal';
  const isEmergency = currentState === 'paid' || urgency === 'critical';
  const isHighAlert = currentState === 'entered_credentials' || urgency === 'urgent';
  const isCaution = currentState === 'clicked';

  // Distinct container style based on severity level with Light & Dark theme support
  let containerStyle = "border-slate-200 bg-white dark:border-border-dark dark:bg-surface-dark-elevated";
  let headerColor = "text-accent dark:text-emerald-400";
  let badgeColor = "bg-emerald-50 text-accent border-emerald-200 dark:bg-surface-dark-hover dark:text-emerald-300 dark:border-border-dark font-bold";

  if (isEmergency) {
    containerStyle = "border-rose-400 bg-rose-50/80 dark:border-rose-600/70 dark:bg-rose-950/25 ring-2 ring-rose-400/30";
    headerColor = "text-rose-600 dark:text-rose-400";
    badgeColor = "bg-rose-100 text-rose-900 border-rose-300 font-bold dark:bg-rose-900/80 dark:text-rose-200 dark:border-rose-500 animate-pulse";
  } else if (isHighAlert) {
    containerStyle = "border-amber-400 bg-amber-50/60 dark:border-amber-600/70 dark:bg-amber-950/20";
    headerColor = "text-amber-700 dark:text-amber-400";
    badgeColor = "bg-amber-100 text-amber-900 border-amber-300 font-bold dark:bg-amber-900/60 dark:text-amber-200 dark:border-amber-600";
  } else if (isCaution) {
    containerStyle = "border-amber-300 bg-slate-50/80 dark:border-border-dark dark:bg-surface-dark-elevated";
    headerColor = "text-amber-700 dark:text-amber-300";
    badgeColor = "bg-amber-50 text-amber-800 border-amber-200 dark:bg-surface-dark-hover dark:text-amber-300 dark:border-border-dark";
  }

  return (
    <section className={`clean-card clean-card-hover p-5 sm:p-6 transition-all duration-300 shadow-sm ${containerStyle}`} aria-label="Adaptive Citizen Guidance">
      {/* Header Bar */}
      <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-200 dark:border-border-dark">
        <div className="flex items-center space-x-2">
          <ShieldAlert className={`w-5 h-5 ${headerColor}`} />
          <h3 className="text-base font-bold text-slate-900 dark:text-white">
            Recommended Citizen Actions
          </h3>
        </div>
        <span className={`px-2.5 py-0.5 rounded-full text-[11px] font-mono border ${badgeColor}`}>
          {isEmergency ? 'EMERGENCY PROTOCOL' : urgency.toUpperCase()}
        </span>
      </div>

      {/* Emergency Callout if Paid / Critical */}
      {isEmergency && (
        <div className="mb-4 p-4 bg-rose-100/80 border border-rose-300 dark:bg-rose-950/70 dark:border-rose-700 rounded-xl text-rose-950 dark:text-rose-200 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 shadow-xs">
          <div className="flex items-center space-x-3">
            <Clock className="w-5 h-5 text-rose-600 dark:text-rose-400 flex-shrink-0 animate-spin" />
            <div>
              <span className="font-bold text-xs uppercase tracking-wide text-rose-900 dark:text-white block">
                Golden Hour Financial Freezing Protocol Active
              </span>
              <p className="text-xs text-rose-800 dark:text-rose-200/90 mt-0.5">
                Banks and UPI gateways can halt fraudulent transactions if notified within 2 hours.
              </p>
            </div>
          </div>
          <a
            href="tel:1930"
            className="inline-flex items-center space-x-1.5 px-4 py-2 bg-rose-600 hover:bg-rose-700 text-white font-bold rounded-xl text-xs shadow-xs transition-transform active:scale-95 flex-shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-500"
          >
            <PhoneCall className="w-4 h-4" />
            <span>Call 1930 Now</span>
          </a>
        </div>
      )}

      {/* Immediate Actions Checklist */}
      {response.immediate_actions && response.immediate_actions.length > 0 && (
        <div className="mb-4">
          <h4 className="text-xs font-bold text-slate-900 dark:text-slate-300 uppercase tracking-wide mb-2 flex items-center space-x-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-500 dark:bg-amber-400" />
            <span>Immediate Actions Checklist</span>
          </h4>
          <ul className="space-y-2">
            {response.immediate_actions.map((act, idx) => (
              <li 
                key={idx} 
                className={`flex items-start space-x-2.5 p-3 rounded-xl text-xs sm:text-sm leading-relaxed ${
                  isEmergency 
                    ? 'bg-rose-100/50 text-rose-950 dark:bg-rose-950/30 dark:text-rose-100 border border-rose-200 dark:border-rose-900/50' 
                    : 'bg-slate-50 text-slate-800 dark:bg-night-950/50 dark:text-slate-200 border border-slate-200 dark:border-night-border'
                }`}
              >
                <CheckCircle2 className={`w-4 h-4 mt-0.5 flex-shrink-0 ${isEmergency ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-600 dark:text-emerald-400'}`} />
                <span className="font-medium">{act}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Recovery Steps Checklist */}
      {response.recovery_steps && response.recovery_steps.length > 0 && (
        <div className="mb-4">
          <h4 className="text-xs font-bold text-slate-900 dark:text-slate-300 uppercase tracking-wide mb-2 flex items-center space-x-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-blue-500 dark:bg-blue-400" />
            <span>Recovery Steps</span>
          </h4>
          <ul className="space-y-1.5">
            {response.recovery_steps.map((step, idx) => (
              <li key={idx} className="flex items-start space-x-2 p-2.5 bg-slate-50 dark:bg-night-950/40 rounded-xl text-xs text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-night-border leading-relaxed">
                <span className="font-mono text-slate-400 font-bold">{idx + 1}.</span>
                <span>{step}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Reporting Channels */}
      {response.reporting_info && response.reporting_info.length > 0 && (
        <div className="mb-4">
          <h4 className="text-xs font-bold text-slate-900 dark:text-slate-300 uppercase tracking-wide mb-2 flex items-center space-x-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-500 dark:bg-amber-500" />
            <span>Official Reporting Channels</span>
          </h4>
          <ul className="space-y-1">
            {response.reporting_info.map((rep, idx) => (
              <li key={idx} className="text-xs text-slate-600 dark:text-slate-400 pl-3 border-l-2 border-slate-300 dark:border-slate-700 py-0.5">
                {rep}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Live Situation Simulator State Machine */}
      <div className="mt-4 pt-3.5 border-t border-slate-200 dark:border-night-border">
        <div className="flex items-center justify-between mb-2.5">
          <span className="text-xs font-semibold text-slate-800 dark:text-slate-300 flex items-center space-x-1.5">
            <RefreshCw className={`w-3.5 h-3.5 text-indigo-500 dark:text-violet-400 ${isUpdatingState ? 'animate-spin' : ''}`} />
            <span>Did your situation change? Update to recalculate:</span>
          </span>
          {isUpdatingState && (
            <span className="text-[11px] text-indigo-600 dark:text-violet-400 font-mono">Recalculating...</span>
          )}
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
          <button
            type="button"
            onClick={() => onStateChange('received')}
            disabled={isUpdatingState}
            className={`px-3 py-2 rounded-xl text-xs font-bold border text-center transition-all cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 ${
              currentState === 'received'
                ? 'bg-gradient-to-r from-slate-800 to-slate-900 text-white border-transparent shadow-card-elevated'
                : 'bg-white text-slate-700 border-slate-200 hover:bg-slate-50 dark:bg-surface-dark-hover dark:text-slate-300 dark:border-border-dark dark:hover:bg-surface-dark-hover'
            }`}
          >
            1. Only Received
          </button>

          <button
            type="button"
            onClick={() => onStateChange('clicked')}
            disabled={isUpdatingState}
            className={`px-3 py-2 rounded-xl text-xs font-bold border text-center transition-all cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-amber-500 ${
              currentState === 'clicked'
                ? 'bg-amber-600 text-white border-amber-700 shadow-sm'
                : 'bg-white text-slate-700 border-slate-200 hover:bg-slate-50 dark:bg-surface-dark-hover dark:text-slate-300 dark:border-border-dark dark:hover:bg-surface-dark-hover'
            }`}
          >
            2. Clicked Link
          </button>

          <button
            type="button"
            onClick={() => onStateChange('entered_credentials')}
            disabled={isUpdatingState}
            className={`px-3 py-2 rounded-xl text-xs font-bold border text-center transition-all cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-orange-500 ${
              currentState === 'entered_credentials'
                ? 'bg-orange-600 text-white border-orange-700 shadow-sm'
                : 'bg-white text-slate-700 border-slate-200 hover:bg-slate-50 dark:bg-surface-dark-hover dark:text-slate-300 dark:border-border-dark dark:hover:bg-surface-dark-hover'
            }`}
          >
            3. Entered Details
          </button>

          <button
            type="button"
            onClick={() => onStateChange('paid')}
            disabled={isUpdatingState}
            className={`px-3 py-2 rounded-xl text-xs font-bold border text-center transition-all cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-500 ${
              currentState === 'paid'
                ? 'bg-rose-600 text-white border-rose-700 shadow-xs animate-pulse'
                : 'bg-rose-50 text-rose-700 border-rose-200 hover:bg-rose-100 dark:bg-rose-950/40 dark:text-rose-300 dark:border-rose-900/60 dark:hover:bg-rose-900/50'
            }`}
          >
            4. Sent Money
          </button>
        </div>
      </div>
    </section>
  );
}
