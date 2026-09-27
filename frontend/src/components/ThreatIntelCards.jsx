import React from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  CheckCircle,
  MinusCircle,
  Radio,
  Info
} from 'lucide-react';

const AUTHORITATIVE_PROVIDERS = [
  {
    key: 'safe_browsing',
    altKeys: ['google_safe_browsing', 'safebrowsing'],
    name: 'Google Safe Browsing',
    feedType: 'v4 Threat List API',
    reliability: 'External Database (Deterministic)',
  },
  {
    key: 'phishtank',
    altKeys: ['pt'],
    name: 'PhishTank',
    feedType: 'Verified Phishing Community Database',
    reliability: 'Community Verified Database',
  },
  {
    key: 'phishstats',
    altKeys: ['ps'],
    name: 'PhishStats',
    feedType: 'Real-time Phishing Threat Intelligence Feed',
    reliability: 'Continuous Phishing Intelligence',
  },
];

// Evaluates intelligence 4-state per provider
function evaluateProviderState(item, provider) {
  // If provider was not queried (no URL extracted or unqueried)
  if (!item) {
    return {
      status: 'NOT CONFIGURED',
      badgeClass: 'bg-slate-100 text-slate-700 border-slate-300 dark:bg-slate-800 dark:text-slate-400 dark:border-slate-700',
      icon: MinusCircle,
      iconColor: 'text-slate-400 dark:text-slate-500',
      cardClass: 'border-slate-200 bg-slate-50/60 dark:border-slate-800 dark:bg-slate-900/40',
      result: 'No extracted URL to evaluate or feed unqueried.',
      confidence: 'Neutral',
      reliability: provider.reliability,
      isMatch: false,
      note: 'Neutral state: Provider was not queried for this input.',
    };
  }

  // Explicit unconfigured / missing API key
  if (
    item.intel_status === 'SOURCE_UNAVAILABLE' ||
    (item.error && item.error.toLowerCase().includes('not configured')) ||
    item.status === 'not_configured'
  ) {
    return {
      status: 'NOT CONFIGURED',
      badgeClass: 'bg-slate-100 text-slate-700 border-slate-300 dark:bg-slate-800 dark:text-slate-400 dark:border-slate-700',
      icon: MinusCircle,
      iconColor: 'text-slate-400 dark:text-slate-500',
      cardClass: 'border-slate-200 bg-slate-50/60 dark:border-slate-800 dark:bg-slate-900/40',
      result: item.error || 'API key not configured in environment.',
      confidence: 'Neutral',
      reliability: provider.reliability,
      isMatch: false,
      note: 'Neutral state: Provider inactive, does not alter risk assessment.',
    };
  }

  // Rate-limiting check
  if (
    item.intel_status === 'RATE_LIMITED' ||
    (item.error && item.error.toLowerCase().includes('rate limit'))
  ) {
    return {
      status: 'RATE LIMITED',
      badgeClass: 'bg-amber-100 text-amber-800 border-amber-300 dark:bg-amber-950 dark:text-amber-300 dark:border-amber-700',
      icon: AlertTriangle,
      iconColor: 'text-amber-600 dark:text-amber-400',
      cardClass: 'border-amber-300 bg-amber-50/50 dark:border-amber-800/50 dark:bg-amber-950/20',
      result: item.error || 'API query threshold reached.',
      confidence: 'Indeterminate',
      reliability: provider.reliability,
      isMatch: false,
      note: 'Provider rate-limited; could not retrieve result.',
    };
  }

  // Feed errors / timeouts
  if (
    item.intel_status === 'SOURCE_ERROR' ||
    item.intel_status === 'FEED_ERROR' ||
    (item.error && (item.error.toLowerCase().includes('timeout') || item.error.toLowerCase().includes('error')))
  ) {
    return {
      status: 'UNAVAILABLE / ERROR',
      badgeClass: 'bg-amber-100 text-amber-800 border-amber-300 dark:bg-amber-950 dark:text-amber-300 dark:border-amber-700',
      icon: AlertTriangle,
      iconColor: 'text-amber-600 dark:text-amber-400',
      cardClass: 'border-amber-300 bg-amber-50/50 dark:border-amber-800/50 dark:bg-amber-950/20',
      result: item.error || 'Temporary timeout or network failure reaching feed.',
      confidence: 'Indeterminate',
      reliability: provider.reliability,
      isMatch: false,
      note: 'Lookup failed due to upstream network error.',
    };
  }

  // Positive Threat Match (KNOWN MALICIOUS)
  if (
    item.match === true ||
    item.intel_status === 'KNOWN MALICIOUS' ||
    item.intel_status === 'KNOWN_MALICIOUS' ||
    item.is_phish === true
  ) {
    return {
      status: 'MATCH (MALICIOUS)',
      badgeClass: 'bg-red-100 text-red-800 border-red-300 dark:bg-red-950 dark:text-red-300 dark:border-red-700',
      icon: ShieldAlert,
      iconColor: 'text-red-600 dark:text-red-400',
      cardClass: 'border-red-300 bg-red-50/70 dark:border-red-800/80 dark:bg-red-950/25',
      result: item.details || item.threat_type || 'Observed in threat repository as active malicious target.',
      confidence: '95% (High)',
      reliability: provider.reliability,
      isMatch: true,
      note: 'Positive threat intelligence match. Immediate high risk indicator.',
    };
  }

  // Clean / No Match
  if (
    item.match === false ||
    item.intel_status === 'NO KNOWN MATCH' ||
    item.intel_status === 'NO_KNOWN_MATCH' ||
    item.status === 'clean'
  ) {
    return {
      status: 'NO MATCH',
      badgeClass: 'bg-slate-100 text-slate-800 border-slate-300 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700',
      icon: CheckCircle,
      iconColor: 'text-slate-600 dark:text-slate-400',
      cardClass: 'border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900',
      result: item.details || 'Feed queried: URL has no known listing in database.',
      confidence: 'Verified Absence',
      reliability: provider.reliability,
      isMatch: false,
      note: 'Absence of a match does NOT guarantee the URL is safe.',
    };
  }

  // Neutral fallback
  return {
    status: 'NOT CONFIGURED',
    badgeClass: 'bg-slate-100 text-slate-700 border-slate-300 dark:bg-slate-800 dark:text-slate-400 dark:border-slate-700',
    icon: MinusCircle,
    iconColor: 'text-slate-400 dark:text-slate-500',
    cardClass: 'border-slate-200 bg-slate-50/60 dark:border-slate-800 dark:bg-slate-900/40',
    result: item.error || 'Provider not queried or key unconfigured.',
    confidence: 'Neutral',
    reliability: provider.reliability,
    isMatch: false,
    note: 'Neutral state.',
  };
}

export default function ThreatIntelCards({ threatIntel }) {
  // Normalize threatIntel whether it's an Array, an Object, or null
  const rawList = Array.isArray(threatIntel)
    ? threatIntel
    : (threatIntel && typeof threatIntel === 'object')
      ? Object.entries(threatIntel).map(([k, v]) => ({ source: k, ...(typeof v === 'object' ? v : {}) }))
      : [];

  return (
    <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-card p-5 sm:p-6 shadow-sm dark:shadow-card-elevated">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 mb-4 border-b border-slate-200 dark:border-slate-800 gap-2">
        <div className="flex items-center space-x-2">
          <Radio className="w-4 h-4 text-slate-700 dark:text-slate-300" />
          <h3 className="text-sm sm:text-base font-bold text-slate-900 dark:text-white">
            Threat Intelligence Feeds
          </h3>
        </div>
        <div className="flex items-center space-x-2">
          <span className="text-[10px] font-mono px-2 py-0.5 rounded-badge bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
            3-SOURCE MULTI-FEED
          </span>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded-badge bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
            4-STATE EVALUATION
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
        {AUTHORITATIVE_PROVIDERS.map((provider) => {
          const matchItem = rawList.find(
            (item) => item?.source === provider.key || provider.altKeys.includes(item?.source)
          );
          const stateInfo = evaluateProviderState(matchItem, provider);
          const Icon = stateInfo.icon;

          return (
            <div
              key={provider.key}
              className={`p-4 rounded-card border flex flex-col justify-between transition-colors ${stateInfo.cardClass}`}
            >
              <div>
                <div className="flex items-start justify-between gap-2 mb-2">
                  <div>
                    <h4 className="text-xs font-bold text-slate-900 dark:text-slate-100">
                      {provider.name}
                    </h4>
                    <p className="text-[10px] text-slate-500 dark:text-slate-400">
                      {provider.feedType}
                    </p>
                  </div>
                  <Icon className={`w-4 h-4 flex-shrink-0 mt-0.5 ${stateInfo.iconColor}`} />
                </div>

                <div className="mb-2.5">
                  <span
                    className={`inline-block px-2 py-0.5 rounded-badge text-[10px] font-bold border tracking-wider ${stateInfo.badgeClass}`}
                  >
                    {stateInfo.status}
                  </span>
                </div>

                <div className="mb-2.5">
                  <p className="text-[11px] font-medium text-slate-700 dark:text-slate-300 leading-snug">
                    {stateInfo.result}
                  </p>
                </div>
              </div>

              <div className="pt-2.5 border-t border-slate-200/80 dark:border-slate-800/80 space-y-1 text-[10px]">
                <div className="flex justify-between text-slate-500 dark:text-slate-400">
                  <span>Reliability:</span>
                  <span className="font-medium text-slate-700 dark:text-slate-300 truncate ml-1 text-right">
                    {stateInfo.reliability}
                  </span>
                </div>
                <div className="flex justify-between text-slate-500 dark:text-slate-400">
                  <span>Confidence:</span>
                  <span className="font-medium text-slate-700 dark:text-slate-300">
                    {stateInfo.confidence}
                  </span>
                </div>
                {stateInfo.note && (
                  <p className="text-[9.5px] italic text-slate-500 dark:text-slate-400 pt-1 leading-tight flex items-start space-x-1">
                    <Info className="w-3 h-3 flex-shrink-0 text-slate-400 dark:text-slate-500 mt-0.5" />
                    <span>{stateInfo.note}</span>
                  </p>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}
