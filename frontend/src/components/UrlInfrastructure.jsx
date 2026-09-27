import React from 'react';
import { Globe, AlertTriangle, ShieldCheck } from 'lucide-react';

export default function UrlInfrastructure({ urls = [] }) {
  if (!urls || urls.length === 0) return null;

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
          const isSuspicious = item.is_suspicious || item.risk_score > 0.4;
          const signals = item.signals || item.reasons || [];

          return (
            <div 
              key={idx} 
              className="p-3.5 bg-slate-50 dark:bg-slate-950 rounded-btn border border-slate-200 dark:border-slate-800 flex flex-col gap-1.5"
            >
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center space-x-2 truncate">
                  {isSuspicious ? (
                    <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400 flex-shrink-0" />
                  ) : (
                    <ShieldCheck className="w-4 h-4 text-emerald-600 dark:text-emerald-400 flex-shrink-0" />
                  )}
                  <span className="font-mono text-xs sm:text-sm text-slate-800 dark:text-slate-200 truncate font-semibold">
                    {item.domain || item.url}
                  </span>
                </div>

                <span className={`px-2 py-0.5 rounded-badge text-[10px] font-bold ${
                  isSuspicious 
                    ? 'bg-amber-100 text-amber-900 border border-amber-300 dark:bg-amber-950 dark:text-amber-300 dark:border-amber-800' 
                    : 'bg-emerald-100 text-emerald-900 border border-emerald-300 dark:bg-emerald-950 dark:text-emerald-300 dark:border-emerald-800'
                }`}>
                  {isSuspicious ? 'SUSPICIOUS DOMAIN' : 'NO ANOMALIES'}
                </span>
              </div>

              {item.url && item.domain && item.url !== item.domain && (
                <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400 truncate">
                  Full URL: {item.url}
                </div>
              )}

              {signals.length > 0 && (
                <div className="flex flex-wrap gap-1.5 mt-1.5">
                  {signals.map((sig, sIdx) => (
                    <span 
                      key={sIdx} 
                      className="px-2 py-0.5 rounded bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 font-mono text-[10px]"
                    >
                      {typeof sig === 'string' ? sig.replace(/_/g, ' ') : JSON.stringify(sig)}
                    </span>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </section>
  );
}
