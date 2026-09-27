import React from 'react';
import { 
  Network, 
  Fingerprint, 
  Building, 
  Server, 
  Layers
} from 'lucide-react';

export default function FraudDna({ fraudDna, targetBrand, extractedDomain }) {
  if (!fraudDna || !fraudDna.campaign_id) return null;

  const relatedCount = fraudDna.related_incidents?.length || 0;

  return (
    <div className="bg-white dark:bg-slate-900 border border-amber-300 dark:border-amber-600/40 rounded-card p-5 shadow-sm dark:shadow-card">
      {/* Title Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 mb-3 border-b border-slate-200 dark:border-slate-800 gap-2">
        <div className="flex items-center space-x-2">
          <Network className="w-5 h-5 text-amber-500 dark:text-amber-400" />
          <h3 className="text-sm sm:text-base font-bold text-amber-900 dark:text-amber-200">
            Fraud DNA Syndicate Campaign Alert
          </h3>
        </div>
        <div className="flex items-center space-x-2">
          <span className="text-[10px] text-slate-500 dark:text-slate-400 font-mono">CAMPAIGN ID:</span>
          <span className="px-2 py-0.5 rounded-badge bg-amber-100 text-amber-900 border border-amber-300 dark:bg-amber-950 dark:text-amber-300 dark:border-amber-600/60 font-mono text-xs font-bold">
            {fraudDna.campaign_id}
          </span>
        </div>
      </div>

      <p className="text-xs sm:text-sm text-slate-700 dark:text-slate-300 mb-4 leading-relaxed">
        Cross-incident correlation engine detected repeated signature fingerprints matching known cyber fraud syndicate infrastructure.
      </p>

      {/* Campaign Graph View (Institutional Navy / Gold Palette) */}
      <div className="bg-slate-50 dark:bg-slate-950 p-4 rounded-btn border border-slate-200 dark:border-slate-800 mb-3">
        <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-3 flex items-center space-x-1.5">
          <Layers className="w-3.5 h-3.5 text-amber-500 dark:text-amber-400" />
          <span>Syndicate Infrastructure Graph</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
          {/* Node 1: Campaign Cluster */}
          <div className="p-3 bg-white dark:bg-slate-900 rounded-btn border border-amber-200 dark:border-amber-800/60 flex items-center space-x-2.5 shadow-sm">
            <Network className="w-4 h-4 text-amber-500 dark:text-amber-400 flex-shrink-0" />
            <div className="min-w-0">
              <span className="text-[10px] text-slate-500 dark:text-slate-400 block">Campaign Syndicate</span>
              <span className="font-mono text-slate-800 dark:text-slate-200 font-semibold truncate block">
                {fraudDna.campaign_name || fraudDna.campaign_id}
              </span>
            </div>
          </div>

          {/* Node 2: Target Brand / Sector */}
          <div className="p-3 bg-white dark:bg-slate-900 rounded-btn border border-slate-200 dark:border-slate-700 flex items-center space-x-2.5 shadow-sm">
            <Building className="w-4 h-4 text-blue-600 dark:text-blue-400 flex-shrink-0" />
            <div className="min-w-0">
              <span className="text-[10px] text-slate-500 dark:text-slate-400 block">Target Brand Impersonated</span>
              <span className="font-semibold text-slate-800 dark:text-slate-200 truncate block">
                {targetBrand || 'Public Financial Sector'}
              </span>
            </div>
          </div>

          {/* Node 3: Infrastructure / Domain */}
          <div className="p-3 bg-white dark:bg-slate-900 rounded-btn border border-slate-200 dark:border-slate-700 flex items-center space-x-2.5 shadow-sm">
            <Server className="w-4 h-4 text-purple-600 dark:text-purple-400 flex-shrink-0" />
            <div className="min-w-0">
              <span className="text-[10px] text-slate-500 dark:text-slate-400 block">Observed Infrastructure</span>
              <span className="font-mono text-slate-800 dark:text-slate-200 font-semibold truncate block">
                {extractedDomain || 'Disposable Host'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Fingerprint & Related Incidents Details */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between text-xs text-slate-600 dark:text-slate-400 pt-3 border-t border-slate-200 dark:border-slate-800 gap-2">
        <div className="flex items-center space-x-1.5 font-mono">
          <Fingerprint className="w-3.5 h-3.5 text-amber-500 dark:text-amber-400" />
          <span>Fingerprint:</span>
          <code className="text-slate-800 dark:text-slate-300 font-mono text-[11px] bg-slate-100 dark:bg-slate-950 px-1.5 py-0.5 rounded border border-slate-200 dark:border-slate-800">
            {fraudDna.fingerprint || 'N/A'}
          </code>
        </div>

        <div>
          {relatedCount > 0 ? (
            <span className="text-amber-800 dark:text-amber-300 font-semibold">
              Correlated with {relatedCount} cataloged syndicate incidents
            </span>
          ) : (
            <span className="text-slate-500 dark:text-slate-400">
              Initial occurrence of this signature pattern
            </span>
          )}
        </div>
      </div>
    </div>
  );
}
