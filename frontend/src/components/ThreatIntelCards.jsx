import React from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle,
  MinusCircle,
  Radio
} from 'lucide-react';

const PROVIDER_NAMES = {
  google_safe_browsing: 'Google Safe Browsing v4',
  phishtank: 'PhishTank Database',
  phishstats: 'PhishStats Community Feed',
  urlhaus: 'URLhaus Community Feed',
};

// Evaluates intelligence 4-state
function getIntelState(item) {
  // If explicitly flagged malicious
  if (item.match === true || item.intel_status === 'KNOWN_MALICIOUS' || item.is_malicious === true) {
    return {
      status: 'KNOWN MALICIOUS',
      badgeClass: 'bg-red-100 text-red-800 border-red-300 dark:bg-red-950 dark:text-red-300 dark:border-red-700',
      icon: ShieldAlert,
      iconColor: 'text-red-600 dark:text-red-400',
      cardClass: 'border-red-300 bg-red-50/70 dark:border-red-800/80 dark:bg-red-950/20',
      details: item.details || item.threat_type || 'Observed in threat repository as active malicious target.',
    };
  }

  // If clean result (queried and passed)
  if (item.match === false || item.intel_status === 'NO_KNOWN_MATCH' || item.status === 'clean') {
    return {
      status: 'NO KNOWN MATCH (CLEAN)',
      badgeClass: 'bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-950 dark:text-emerald-300 dark:border-emerald-700',
      icon: CheckCircle,
      iconColor: 'text-emerald-600 dark:text-emerald-400',
      cardClass: 'border-emerald-300 bg-emerald-50/60 dark:border-emerald-800/60 dark:bg-emerald-950/10',
      details: item.details || 'Feed queried: URL is not listed as active malware or phishing host.',
    };
  }

  // If feed error or runtime failure (timeout, 5xx, etc.)
  if (item.intel_status === 'FEED_ERROR' || item.error || item.status === 'error') {
    return {
      status: 'FEED TEMPORARILY UNAVAILABLE',
      badgeClass: 'bg-amber-100 text-amber-800 border-amber-300 dark:bg-amber-950 dark:text-amber-300 dark:border-amber-700',
      icon: AlertTriangle,
      iconColor: 'text-amber-600 dark:text-amber-400',
      cardClass: 'border-amber-300 bg-amber-50/60 dark:border-amber-800/50 dark:bg-amber-950/10',
      details: item.error || 'Temporary timeout or network rate limit connecting to feed endpoint.',
    };
  }

  // Neutral Grey for Not configured / Not queried / API key missing (NEVER alarm red!)
  return {
    status: 'NOT CONFIGURED / UNQUERIED',
    badgeClass: 'bg-slate-100 text-slate-700 border-slate-300 dark:bg-slate-800 dark:text-slate-400 dark:border-slate-700',
    icon: MinusCircle,
    iconColor: 'text-slate-500 dark:text-slate-400',
    cardClass: 'border-slate-200 bg-slate-50/80 dark:border-slate-800 dark:bg-slate-950/60',
    details: 'Provider not queried (no URL extracted or API key unconfigured).',
  };
}

export default function ThreatIntelCards({ threatIntel = {} }) {
  const providers = Object.entries(threatIntel);

  if (providers.length === 0) {
    return (
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-card p-5 shadow-sm dark:shadow-card">
        <div className="flex items-center space-x-2 mb-2">
          <Radio className="w-4 h-4 text-amber-500 dark:text-amber-400" />
          <h3 className="text-sm sm:text-base font-bold text-slate-900 dark:text-white">
            Threat Intelligence Feeds
          </h3>
        </div>
        <p className="text-xs text-slate-600 dark:text-slate-400">
          No external web URLs detected in message to correlate against active threat intelligence feeds.
        </p>
      </div>
    );
  }

  return (
    <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-card p-5 sm:p-6 shadow-sm dark:shadow-card-elevated">
      <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-200 dark:border-slate-800">
        <div className="flex items-center space-x-2">
          <Radio className="w-4 h-4 text-amber-500 dark:text-amber-400" />
          <h3 className="text-sm sm:text-base font-bold text-slate-900 dark:text-white">
            Threat Intelligence Feeds
          </h3>
        </div>
        <span className="text-[10px] font-mono px-2 py-0.5 rounded-badge bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
          4-STATE EVALUATION
        </span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        {providers.map(([key, data]) => {
          const feedName = PROVIDER_NAMES[key] || key.replace(/_/g, ' ').toUpperCase();
          const stateInfo = getIntelState(data || {});
          const Icon = stateInfo.icon;

          return (
            <div
              key={key}
              className={`p-3.5 rounded-card border flex flex-col justify-between transition-colors ${stateInfo.cardClass}`}
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-bold text-slate-900 dark:text-slate-200 truncate">
                    {feedName}
                  </span>
                  <Icon className={`w-4 h-4 flex-shrink-0 ${stateInfo.iconColor}`} />
                </div>

                <div className="mb-2">
                  <span className={`inline-block px-1.5 py-0.5 rounded-badge text-[10px] font-bold border ${stateInfo.badgeClass}`}>
                    {stateInfo.status}
                  </span>
                </div>
              </div>

              <p className="text-[11px] text-slate-600 dark:text-slate-400 leading-snug">
                {stateInfo.details}
              </p>
            </div>
          );
        })}
      </div>
    </section>
  );
}
