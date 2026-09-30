import React from 'react';
import { Globe, AlertTriangle, ShieldCheck, ShieldAlert } from 'lucide-react';

export default function UrlInfrastructure({ urls = [], threatIntel = [] }) {
  if (!urls || urls.length === 0) return null;

  // Filter confirmed threat intelligence matches
  const activeThreats = (threatIntel || []).filter(ti => {
    const status = (ti.intel_status || ti.status || '').toUpperCase();
    return (
      status === 'CONFIRMED_MALICIOUS' || 
      status === 'MATCH' || 
      status === 'MATCH (MALICIOUS)' || 
      ti.is_match === true
    );
  });

  return (
    <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-card p-5 shadow-sm dark:shadow-card" aria-label="Extracted Web Infrastructure">
      <div className="flex items-center space-x-2 pb-3 mb-3 border-b border-slate-200 dark:border-slate-800">
        <Globe className="w-5 h-5 text-amber-500 dark:text-amber-400" />
        <h3 className="text-base font-bold text-slate-900 dark:text-white">
          Extracted URLs & Web Infrastructure
        </h3>
      </div>

      <div className="space-y-2.5">
        {urls.map((item, idx) => {
          const itemUrlLower = (item.url || '').toLowerCase();
          const itemDomainLower = (item.domain || '').toLowerCase();

          // Check if this URL or its host matched any live threat intelligence feeds
          const matchedThreat = activeThreats.find(ti => {
            const tiUrl = (ti.url || ti.target || ti.raw_reference || '').toLowerCase();
            const tiHost = (ti.host || ti.domain || '').toLowerCase();
            if (tiUrl && (itemUrlLower.includes(tiUrl) || tiUrl.includes(itemUrlLower))) return true;
            if (tiHost && (itemDomainLower === tiHost || itemDomainLower.endsWith('.' + tiHost))) return true;
            if (urls.length === 1 && activeThreats.length > 0) return true;
            return false;
          });

          // Aggregate signals
          const rawSignals = item.signals || item.reasons || [];
          const signals = [...rawSignals];

          if (matchedThreat && !signals.some(s => s.toLowerCase().includes('browsing') || s.toLowerCase().includes('intel'))) {
            const providerName = matchedThreat.source === 'safe_browsing' ? 'Google Safe Browsing' : (matchedThreat.source || 'Threat Intel');
            const threatType = matchedThreat.threat_type || matchedThreat.details || 'Social Engineering / Phishing';
            signals.unshift(`${providerName}: ${threatType}`);
          }

          const isMalicious = !!matchedThreat || signals.some(s => s.toLowerCase().includes('safe_browsing') || s.toLowerCase().includes('phishtank'));
          const isSuspicious = !isMalicious && (item.is_suspicious || signals.length > 0 || (item.risk_score && item.risk_score > 0.4));

          return (
            <div 
              key={idx} 
              className={`p-3.5 rounded-btn border flex flex-col gap-1.5 transition-colors ${
                isMalicious
                  ? 'bg-red-50/50 dark:bg-red-950/20 border-red-200 dark:border-red-900/60'
                  : 'bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-800'
              }`}
            >
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center space-x-2 truncate">
                  {isMalicious ? (
                    <ShieldAlert className="w-4 h-4 text-red-600 dark:text-red-400 flex-shrink-0" />
                  ) : isSuspicious ? (
                    <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400 flex-shrink-0" />
                  ) : (
                    <ShieldCheck className="w-4 h-4 text-emerald-600 dark:text-emerald-400 flex-shrink-0" />
                  )}
                  <span className="font-mono text-xs sm:text-sm text-slate-800 dark:text-slate-200 truncate font-semibold">
                    {item.domain || item.url}
                  </span>
                </div>

                <span className={`px-2 py-0.5 rounded-badge text-[10px] font-bold ${
                  isMalicious
                    ? 'bg-red-100 text-red-800 border border-red-300 dark:bg-red-950 dark:text-red-300 dark:border-red-800'
                    : isSuspicious 
                      ? 'bg-amber-100 text-amber-900 border border-amber-300 dark:bg-amber-950 dark:text-amber-300 dark:border-amber-800' 
                      : 'bg-emerald-100 text-emerald-900 border border-emerald-300 dark:bg-emerald-950 dark:text-emerald-300 dark:border-emerald-800'
                }`}>
                  {isMalicious ? 'CONFIRMED MALICIOUS' : isSuspicious ? 'SUSPICIOUS PATTERNS' : 'NO SYNTACTIC ANOMALIES'}
                </span>
              </div>

              {item.url && item.domain && item.url !== item.domain && (
                <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400 truncate">
                  Full URL: {item.url}
                </div>
              )}

              {signals.length > 0 && (
                <div className="flex flex-wrap gap-1.5 mt-1.5">
                  {signals.map((sig, sIdx) => {
                    const isThreatSig = typeof sig === 'string' && (sig.includes('Safe Browsing') || sig.includes('PhishTank') || sig.includes('Threat Intel') || sig.includes('safe_browsing'));
                    return (
                      <span 
                        key={sIdx} 
                        className={`px-2 py-0.5 rounded font-mono text-[10px] ${
                          isThreatSig
                            ? 'bg-red-100 text-red-800 border border-red-300 dark:bg-red-950/80 dark:text-red-300 dark:border-red-800 font-semibold'
                            : 'bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300'
                        }`}
                      >
                        {typeof sig === 'string' ? sig.replace(/_/g, ' ') : JSON.stringify(sig)}
                      </span>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </section>
  );
}
