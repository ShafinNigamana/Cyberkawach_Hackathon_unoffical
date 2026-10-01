import React, { useState } from 'react';
import {
  FileCheck,
  Search,
  ChevronDown,
  ChevronUp,
  Globe2,
  Loader2,
  AlertTriangle,
  ChevronsUpDown,
  Maximize2,
  Minimize2
} from 'lucide-react';
import { fetchIncidentOsint } from '../services/api';

// Helper to determine source label and unified epistemic status
function getProvenanceDetails(itemOrSource, type, rawStatus, tier) {
  let source = itemOrSource;
  let riskDirection = '';
  let finding = '';
  let severity = '';

  if (typeof itemOrSource === 'object' && itemOrSource !== null) {
    source = itemOrSource.source;
    type = itemOrSource.type;
    rawStatus = itemOrSource.status;
    tier = itemOrSource.evidence_tier;
    riskDirection = itemOrSource.risk_direction || '';
    finding = itemOrSource.finding || itemOrSource.description || '';
    severity = itemOrSource.severity || '';
  }

  const s = (source || '').toLowerCase();
  const t = (type || '').toLowerCase();
  const tierUpper = (tier || '').toUpperCase();
  const statusUpper = (rawStatus || '').toUpperCase();
  const riskUpper = (riskDirection || '').toUpperCase();
  const findingLower = (finding || '').toLowerCase();

  let sourceLabel = source || 'Forensic Module';

  if (s.includes('dns') || t.includes('dns')) {
    sourceLabel = 'DNS Records';
  } else if (s.includes('tls') || t.includes('tls')) {
    sourceLabel = 'TLS Certificate';
  } else if (s.includes('website') || t.includes('website') || s.includes('sandbox')) {
    sourceLabel = 'Live Website Scanner';
  } else if (s.includes('financial') || s.includes('ifsc') || s.includes('upi') || s.includes('razorpay')) {
    sourceLabel = 'Banking & UPI OSINT';
  } else if (s.includes('sender') || t.includes('sender') || s.includes('telecom') || s.includes('carrier') || s.includes('phonenumber')) {
    sourceLabel = 'Sender & Telecom OSINT';
  } else if (s.includes('urlhaus')) {
    sourceLabel = 'URLhaus Feed';
  } else if (s.includes('openphish')) {
    sourceLabel = 'OpenPhish Feed';
  } else if (s.includes('virustotal')) {
    sourceLabel = 'VirusTotal Feed';
  } else if (s.includes('rule') || t.includes('rule')) {
    sourceLabel = 'Rule Engine';
  } else if (s.includes('laya') || t.includes('laya')) {
    sourceLabel = 'Fast Decision (Laya)';
  } else if (s.includes('ml_classifier') || s.includes('ml') || t.includes('ml')) {
    sourceLabel = 'ML Classifier (Scikit-Learn)';
  } else if (s.includes('threat') || s.includes('safe_browsing') || s.includes('phishtank') || s.includes('phishstats')) {
    sourceLabel = 'Threat Intel Feed';
  } else if (s.includes('url') || t.includes('url')) {
    sourceLabel = 'URL Analyzer';
  } else if (s.includes('brand') || t.includes('brand')) {
    sourceLabel = 'Brand Check';
  } else if (s.includes('osint') || t.includes('osint') || s.includes('whois') || s.includes('rdap')) {
    sourceLabel = 'RDAP / WHOIS';
  }

  // Tier / status badge determination
  let tierBadge = {
    label: tierUpper || 'OBSERVED',
    badgeClass: 'bg-slate-100 text-slate-700 border-slate-300 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700',
  };

  const isFeedUnavailable =
    statusUpper === 'UNAVAILABLE' ||
    tierUpper === 'UNAVAILABLE' ||
    findingLower.includes('unavailable') ||
    findingLower.includes('http 401') ||
    findingLower.includes('http 403');

  const isThreatMiss =
    t === 'threat_intel_miss' ||
    findingLower.includes('no malicious match') ||
    findingLower.includes('clean/unlisted') ||
    findingLower.includes('no record of malicious');

  const isPositiveThreat =
    t === 'threat_intel_hit' ||
    (riskUpper === 'INCREASES_RISK' && (tierUpper === 'DIRECT' || statusUpper === 'CONFIRMED')) ||
    findingLower.includes('confirmed active threat') ||
    findingLower.includes('known malicious');

  if (isFeedUnavailable) {
    tierBadge = {
      label: 'FEED UNAVAILABLE',
      badgeClass: 'bg-slate-100 text-slate-600 border-slate-300 dark:bg-slate-800 dark:text-slate-400 dark:border-slate-700',
    };
  } else if (isThreatMiss) {
    tierBadge = {
      label: 'UNLISTED / CLEAN',
      badgeClass: 'bg-slate-100 text-slate-700 border-slate-300 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700',
    };
  } else if (isPositiveThreat) {
    tierBadge = {
      label: 'DIRECT THREAT',
      badgeClass: 'bg-red-100 text-red-800 border-red-300 dark:bg-red-950/80 dark:text-red-200 dark:border-red-800',
    };
  } else if (statusUpper === 'CONFIRMED') {
    tierBadge = {
      label: 'CONFIRMED FACT',
      badgeClass: 'bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-950/60 dark:text-emerald-300 dark:border-emerald-800',
    };
  } else if (tierUpper === 'DERIVED' || statusUpper === 'SUSPICIOUS' || riskUpper === 'INCREASES_RISK') {
    tierBadge = {
      label: tierUpper === 'DERIVED' ? 'DERIVED INTEL' : 'SUSPICIOUS SIGNAL',
      badgeClass: 'bg-amber-100 text-amber-800 border-amber-300 dark:bg-amber-950/70 dark:text-amber-200 dark:border-amber-800',
    };
  } else if (tierUpper === 'WEAK_SIGNAL') {
    tierBadge = {
      label: 'HEURISTIC SIGNAL',
      badgeClass: 'bg-purple-100 text-purple-800 border-purple-300 dark:bg-purple-950/60 dark:text-purple-300 dark:border-purple-800',
    };
  }

  return { sourceLabel, statusBadge: tierBadge };
}

export default function EvidenceSection({
  evidenceItems = [],
  incidentId,
  extractedDomain
}) {
  const [osintLoading, setOsintLoading] = useState(false);
  const [osintData, setOsintData] = useState(null);
  const [osintError, setOsintError] = useState(null);

  // Progressive Disclosure: accordion state (default collapsed)
  const [expandedIndices, setExpandedIndices] = useState(new Set());

  const handleFetchOsint = async () => {
    if (!incidentId) return;
    setOsintLoading(true);
    setOsintError(null);
    try {
      const data = await fetchIncidentOsint(incidentId);
      setOsintData(data);
    } catch (err) {
      setOsintError(err.message || 'Unable to enrich OSINT at this time.');
    } finally {
      setOsintLoading(false);
    }
  };

  const allEvidence = [...evidenceItems, ...(osintData?.evidence || [])];

  const toggleAccordion = (idx) => {
    setExpandedIndices(prev => {
      const next = new Set(prev);
      if (next.has(idx)) {
        next.delete(idx);
      } else {
        next.add(idx);
      }
      return next;
    });
  };

  const toggleAllAccordions = () => {
    if (expandedIndices.size === allEvidence.length) {
      setExpandedIndices(new Set());
    } else {
      setExpandedIndices(new Set(allEvidence.map((_, i) => i)));
    }
  };

  const isAllExpanded = allEvidence.length > 0 && expandedIndices.size === allEvidence.length;

  return (
    <section className="luxury-card p-6 shadow-sm" aria-label="Factual Evidence Section">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 mb-4 border-b border-slate-200 dark:border-night-border gap-3">
        <div className="flex items-center space-x-3">
          <div className="w-9 h-9 rounded-xl bg-indigo-50 dark:bg-night-800 text-indigo-600 dark:text-violet-400 flex items-center justify-center flex-shrink-0">
            <FileCheck className="w-4.5 h-4.5" />
          </div>
          <h3 className="text-base sm:text-lg font-bold text-slate-900 dark:text-white">
            Forensic Evidence Items
          </h3>
          <span className="px-2.5 py-0.5 rounded-full bg-slate-100 dark:bg-night-800 text-slate-800 dark:text-slate-200 font-mono text-xs font-bold border border-slate-200 dark:border-night-border">
            {allEvidence.length}
          </span>
        </div>

        {/* Action Controls: Expand/Collapse All */}
        <div className="flex items-center space-x-2">
          {allEvidence.length > 0 && (
            <button
              type="button"
              onClick={toggleAllAccordions}
              className="inline-flex items-center space-x-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-300 dark:bg-night-800 dark:hover:bg-night-750 dark:text-slate-300 dark:border-night-border transition-colors cursor-pointer"
              title={isAllExpanded ? "Collapse all evidence accordions" : "Expand all evidence accordions"}
            >
              {isAllExpanded ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
              <span>{isAllExpanded ? 'Collapse All' : 'Expand All Evidence'}</span>
            </button>
          )}
        </div>
      </div>

      <p className="text-xs text-slate-600 dark:text-slate-400 mb-4 leading-relaxed">
        Evidence contract: each item shows its source module, confidence score, and one concise finding. Click any row to reveal observed technical tokens and analytical significance.
      </p>

      {/* Asynchronous OSINT Trigger (if domain available) */}
      {extractedDomain && !osintData && (
        <div className="mb-4 p-3.5 bg-slate-50/80 dark:bg-night-950/80 rounded-xl border border-slate-200 dark:border-night-border flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center space-x-2.5 truncate">
            <Globe2 className="w-4 h-4 text-indigo-500 dark:text-violet-400 flex-shrink-0" />
            <span className="text-xs text-slate-700 dark:text-slate-300 truncate">
              Domain Target: <code className="text-slate-900 dark:text-slate-100 font-mono font-semibold">{extractedDomain}</code>
            </span>
          </div>

          <button
            type="button"
            onClick={handleFetchOsint}
            disabled={osintLoading}
            className="inline-flex items-center space-x-1.5 px-3.5 py-1.5 bg-slate-900 hover:bg-slate-800 text-white dark:bg-gradient-to-r dark:from-indigo-600 dark:to-violet-600 text-xs font-bold rounded-lg shadow-sm transition-all disabled:opacity-50 cursor-pointer self-start sm:self-auto flex-shrink-0"
          >
            {osintLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Search className="w-3.5 h-3.5" />}
            <span>Query Live OSINT (WHOIS & CT)</span>
          </button>
        </div>
      )}

      {/* OSINT Error Notice */}
      {osintError && (
        <div className="mb-4 p-2.5 bg-amber-50 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-800/60 rounded-xl text-xs text-amber-800 dark:text-amber-300 flex items-center space-x-2">
          <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400 flex-shrink-0" />
          <span>{osintError}</span>
        </div>
      )}

      {/* Collapsed Accordion Evidence Rows */}
      <div className="space-y-2.5" role="region" aria-label="Evidence Items Accordion List">
        {allEvidence.map((item, idx) => {
          const { sourceLabel, statusBadge } = getProvenanceDetails(item);
          const confidence = item.confidence != null ? `${Math.round(item.confidence * 100)}%` : '--';
          const isExpanded = expandedIndices.has(idx);

          return (
            <div
              key={idx}
              className={`rounded-xl border transition-all duration-200 overflow-hidden ${isExpanded
                  ? 'bg-slate-50/80 border-slate-300 dark:bg-night-800/90 dark:border-violet-500/40 shadow-sm'
                  : 'bg-white/80 hover:bg-slate-50/80 border-slate-200 dark:bg-night-850/60 hover:dark:bg-night-800/60 dark:border-night-border'
                }`}
            >
              {/* Accordion Header (Interactive Button) */}
              <button
                type="button"
                onClick={() => toggleAccordion(idx)}
                aria-expanded={isExpanded}
                className="w-full text-left p-3.5 flex items-start sm:items-center justify-between gap-2.5 focus:outline-none focus:ring-2 focus:ring-cyan-500/40 cursor-pointer"
              >
                <div className="flex-1 min-w-0 flex flex-col sm:flex-row sm:items-center gap-1.5 sm:gap-2.5">
                  <div className="flex items-center space-x-1.5 flex-wrap flex-shrink-0">
                    {/* Consistent Source Tag */}
                    <span className="px-2 py-0.5 rounded-badge bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300 text-[10px] font-bold border border-slate-300 dark:border-slate-700">
                      {sourceLabel}
                    </span>

                    {/* Unified Tier/Status Badge */}
                    <span className={`px-2 py-0.5 rounded-badge text-[10px] font-bold border ${statusBadge.badgeClass}`}>
                      {statusBadge.label}
                    </span>

                    {/* LIVE vs CACHED Badge */}
                    {item.is_cached ? (
                      <span className="px-1.5 py-0.2 rounded text-[9px] font-mono bg-slate-100 text-slate-500 border border-slate-300 dark:bg-slate-800 dark:text-slate-400">
                        CACHED
                      </span>
                    ) : (
                      <span className="px-1.5 py-0.2 rounded text-[9px] font-mono bg-blue-50 text-blue-600 border border-blue-200 dark:bg-blue-950/60 dark:text-blue-300">
                        LIVE
                      </span>
                    )}
                  </div>

                  {/* One-Line Plain-Language Conclusion */}
                  <span className="text-xs sm:text-sm font-medium text-slate-800 dark:text-slate-200 line-clamp-1">
                    {item.finding || item.description}
                  </span>
                </div>

                {/* Right: Confidence Score & Accordion Chevron */}
                <div className="flex items-center space-x-2 flex-shrink-0">
                  <span className="font-mono text-xs font-bold text-amber-600 dark:text-amber-400">
                    {confidence}
                  </span>
                  <div className="p-1 text-slate-400">
                    {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                  </div>
                </div>
              </button>

              {/* Accordion Body (Revealed on Click) */}
              {isExpanded && (
                <div className="px-3.5 pb-3.5 pt-1 border-t border-slate-200/80 dark:border-slate-800/80 text-xs space-y-2">
                  {/* Full Description if truncated */}
                  <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed font-normal">
                    {item.description}
                  </p>

                  {/* Observed Technical Fact (Short Tokens Only) */}
                  {item.observed_value && (
                    <div className="p-2.5 bg-slate-100 dark:bg-slate-900 rounded border border-slate-200 dark:border-slate-800">
                      <div className="flex items-start space-x-1.5">
                        <span className="text-[11px] font-bold text-slate-700 dark:text-slate-300 flex-shrink-0">
                          Observed Token:
                        </span>
                        <code className="text-[11px] font-mono font-medium text-blue-700 dark:text-amber-300 break-all">
                          {item.observed_value}
                        </code>
                      </div>
                    </div>
                  )}

                  {/* Analytical Significance / Interpretation */}
                  {item.interpretation && (
                    <div className="text-xs text-slate-600 dark:text-slate-400 flex items-start space-x-1.5">
                      <span className="font-semibold text-slate-800 dark:text-slate-200 flex-shrink-0">
                        Significance:
                      </span>
                      <span className="leading-relaxed">
                        {item.interpretation}
                      </span>
                    </div>
                  )}

                  {item.correlation_group && (
                    <div className="text-[10px] text-slate-500 font-mono">
                      Correlated Group: {item.correlation_group}
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </section>
  );
}
