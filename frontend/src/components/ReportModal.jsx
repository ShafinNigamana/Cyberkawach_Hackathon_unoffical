import React, { useState } from 'react';
import { 
  X, 
  Printer, 
  Download, 
  ExternalLink, 
  ShieldAlert, 
  Copy, 
  Check 
} from 'lucide-react';
import { getExportUrl } from '../services/api';

export default function ReportModal({ 
  isOpen = true, 
  incident, 
  result, 
  incidentId, 
  onClose, 
  onCopyRef, 
  copiedRef 
}) {
  const [internalCopied, setInternalCopied] = useState(false);

  if (isOpen === false) return null;

  const currentIncident = incident || result;
  if (!currentIncident) return null;

  const effectiveId = incidentId || currentIncident.incident_id || 'INC-2026-PENDING';
  const exportJsonUrl = getExportUrl(effectiveId, 'json');
  const exportHtmlUrl = getExportUrl(effectiveId, 'html');

  const riskScorePct = Math.round((currentIncident.risk?.score || 0) * 100);
  const riskLevel = (currentIncident.risk?.level || 'UNKNOWN').toUpperCase();

  const handleCopy = (refId) => {
    if (onCopyRef) {
      onCopyRef(refId);
    } else {
      navigator.clipboard?.writeText?.(refId);
      setInternalCopied(true);
      setTimeout(() => setInternalCopied(false), 2000);
    }
  };

  const isCopied = copiedRef ?? internalCopied;

  const handlePrint = () => {
    window.print();
  };

  const handleDownloadJson = (e) => {
    e.preventDefault();
    try {
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(currentIncident, null, 2));
      const a = document.createElement('a');
      a.setAttribute("href", dataStr);
      a.setAttribute("download", `CyberKawach_${effectiveId}_dossier.json`);
      document.body.appendChild(a);
      a.click();
      a.remove();
    } catch {
      window.open(exportJsonUrl, '_blank');
    }
  };

  return (
    <div 
      className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-slate-950/80 backdrop-blur-md overflow-y-auto animate-fade-in"
      role="dialog"
      aria-modal="true"
      aria-label="Forensic Incident Dossier Preview"
    >
      <div className="bg-white dark:bg-night-900 border border-slate-200 dark:border-night-border rounded-2xl max-w-4xl w-full max-h-[90vh] flex flex-col shadow-2xl text-slate-800 dark:text-slate-200 overflow-hidden">
        {/* Modal Top Bar */}
        <div className="flex items-center justify-between p-4 sm:p-5 border-b border-slate-200 dark:border-night-border bg-slate-50 dark:bg-night-950">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-xl bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20 flex items-center justify-center">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm sm:text-base font-bold text-slate-900 dark:text-white">
                Official Cyber Crime Forensic Incident Dossier
              </h3>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">
                Citizen Technical Pack for National Cyber Crime Helpline (1930) & State Police
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={handlePrint}
              className="inline-flex items-center space-x-1.5 px-3 py-1.5 btn-primary text-xs shadow cursor-pointer"
              title="Print official dossier or save to PDF"
            >
              <Printer className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Print / Save PDF</span>
              <span className="sm:hidden">Print</span>
            </button>

            <button
              onClick={handleDownloadJson}
              className="inline-flex items-center space-x-1.5 px-3 py-1.5 btn-secondary text-xs cursor-pointer"
              title="Download structured JSON forensic export"
            >
              <Download className="w-3.5 h-3.5" />
              <span>JSON</span>
            </button>

            <button
              onClick={onClose}
              className="p-1.5 rounded-lg hover:bg-slate-200 dark:hover:bg-night-800 text-slate-400 hover:text-slate-700 dark:hover:text-white transition-colors cursor-pointer"
              aria-label="Close Preview"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Printable Document Preview Area */}
        <div className="p-5 sm:p-8 overflow-y-auto space-y-6 font-sans text-xs bg-slate-50/50 dark:bg-night-950/60 print:bg-white print:text-black">
          {/* Official Emblem Banner */}
          <div className="text-center pb-4 border-b border-slate-200 dark:border-night-border">
            <div className="inline-block p-2.5 bg-white dark:bg-night-800 rounded-2xl border border-slate-200 dark:border-night-border mb-2.5 shadow-xs">
              <svg viewBox="0 0 24 24" width="28" height="28" fill="currentColor" className="text-amber-500 dark:text-amber-400 mx-auto" aria-hidden="true">
                <circle cx="12" cy="12" r="10" fill="none" stroke="currentColor" strokeWidth="1.5" />
                <circle cx="12" cy="12" r="2" fill="currentColor" />
                <path d="M12 2v20M2 12h20M4.93 4.93l14.14 14.14M4.93 19.07L19.07 4.93M8.46 2.54l7.08 18.92M2.54 8.46l18.92 7.08M15.54 2.54L8.46 21.46M2.54 15.54l18.92-7.08" stroke="currentColor" strokeWidth="0.8" />
              </svg>
            </div>
            <h2 className="text-base font-bold text-slate-900 dark:text-white uppercase tracking-wider">
              CYBER FRAUD FORENSIC INCIDENT DOSSIER
            </h2>
            <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
              Generated by Cyber Fraud Guardian • I4C Partner Initiative • Track S2
            </p>
          </div>

          {/* Dossier Identifiers Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 p-4 bg-white dark:bg-night-800/80 rounded-xl border border-slate-200 dark:border-night-border font-mono text-xs shadow-xs">
            <div>
              <span className="text-slate-500 dark:text-slate-400 block text-[10px] font-sans font-bold uppercase tracking-wider">INCIDENT REFERENCE ID:</span>
              <div className="flex items-center space-x-2 mt-1">
                <strong className="text-indigo-600 dark:text-amber-400 text-sm font-mono tracking-wide">{effectiveId}</strong>
                <button
                  onClick={() => handleCopy(effectiveId)}
                  className="p-1 hover:bg-slate-100 dark:hover:bg-night-700 rounded text-slate-400 hover:text-slate-700 dark:hover:text-white cursor-pointer transition-colors"
                  title="Copy Reference ID"
                >
                  {isCopied ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
            </div>

            <div>
              <span className="text-slate-500 dark:text-slate-400 block text-[10px] font-sans font-bold uppercase tracking-wider">THREAT CLASSIFICATION:</span>
              <div className="mt-1 flex items-center flex-wrap gap-2">
                <span className={`inline-block px-2.5 py-0.5 rounded-full text-xs font-bold border ${
                  riskLevel === 'CRITICAL' || riskLevel === 'HIGH' 
                    ? 'bg-rose-50 text-rose-700 border-rose-200 dark:bg-rose-950/60 dark:text-rose-300 dark:border-rose-800' 
                    : 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/60 dark:text-emerald-300 dark:border-emerald-800'
                }`}>
                  {riskLevel} ({riskScorePct}/100)
                </span>
                <span className="text-slate-600 dark:text-slate-400 text-xs font-sans">
                  Category: <strong className="text-slate-800 dark:text-slate-200">{currentIncident.fraud_category || 'General Scam'}</strong>
                </span>
              </div>
            </div>
          </div>

          {/* Section 1: Untrusted Evidentiary Message */}
          <div>
            <h4 className="text-xs font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider mb-2">
              1. Untrusted Evidentiary Communication
            </h4>
            <div className="p-3.5 bg-white dark:bg-night-950 border border-slate-200 dark:border-night-border rounded-xl font-mono text-[11px] text-slate-700 dark:text-slate-300 whitespace-pre-wrap break-words leading-relaxed shadow-xs">
              {currentIncident.message_preview || currentIncident.message || 'No text content available'}
            </div>
          </div>

          {/* Section 2: Indicators of Compromise (IOCs) */}
          {currentIncident.urls && currentIncident.urls.length > 0 && (
            <div>
              <h4 className="text-xs font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider mb-2">
                2. Extracted Indicators of Compromise (IOCs)
              </h4>
              <div className="overflow-x-auto border border-slate-200 dark:border-night-border rounded-xl shadow-xs">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="bg-slate-100 dark:bg-night-800 border-b border-slate-200 dark:border-night-border text-slate-600 dark:text-slate-400 font-mono text-[11px]">
                      <th className="p-3">Type</th>
                      <th className="p-3">Observed Value / URL</th>
                      <th className="p-3">Classification</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-night-border font-mono bg-white dark:bg-night-900/60">
                    {currentIncident.urls.map((u, i) => (
                      <tr key={i} className="hover:bg-slate-50 dark:hover:bg-night-800/40">
                        <td className="p-3 text-slate-500 dark:text-slate-400">Web URL</td>
                        <td className="p-3 text-slate-800 dark:text-slate-200 break-all">{u.url}</td>
                        <td className="p-3">
                          <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                            u.is_suspicious 
                              ? 'bg-rose-50 text-rose-700 dark:bg-rose-950/60 dark:text-rose-300' 
                              : 'bg-emerald-50 text-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-300'
                          }`}>
                            {u.is_suspicious ? 'Suspicious' : 'Clean'}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Section 3: Evidence Summary Table */}
          {currentIncident.evidence && currentIncident.evidence.length > 0 && (
            <div>
              <h4 className="text-xs font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider mb-2">
                3. Forensic Evidence Dossier
              </h4>
              <div className="overflow-x-auto border border-slate-200 dark:border-night-border rounded-xl shadow-xs">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="bg-slate-100 dark:bg-night-800 border-b border-slate-200 dark:border-night-border text-slate-600 dark:text-slate-400 font-mono text-[11px]">
                      <th className="p-3">Source Module</th>
                      <th className="p-3">Finding & Forensic Description</th>
                      <th className="p-3">Confidence</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-night-border bg-white dark:bg-night-900/60">
                    {currentIncident.evidence.map((item, i) => (
                      <tr key={i} className="hover:bg-slate-50 dark:hover:bg-night-800/40">
                        <td className="p-3 font-mono text-slate-500 dark:text-slate-400 whitespace-nowrap">{item.source}</td>
                        <td className="p-3 text-slate-800 dark:text-slate-200">{item.description}</td>
                        <td className="p-3 font-mono text-amber-600 dark:text-amber-400 font-bold whitespace-nowrap">
                          {item.confidence != null ? `${Math.round(item.confidence * 100)}%` : '100%'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Section 4: National Helpline Advisory */}
          <div className="p-4 bg-amber-500/5 dark:bg-amber-500/10 rounded-xl border border-amber-500/20 text-slate-700 dark:text-slate-300 space-y-1.5">
            <h4 className="text-xs font-bold text-slate-900 dark:text-white uppercase tracking-wider flex items-center space-x-1.5">
              <span>National Cyber Crime Reporting Advisory</span>
            </h4>
            <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
              If financial loss occurred within the last 24 hours (Golden Hour), immediately call <strong>1930</strong> or register an online formal complaint at <a href="https://cybercrime.gov.in" target="_blank" rel="noreferrer" className="text-indigo-600 dark:text-indigo-400 underline font-medium">https://cybercrime.gov.in</a> quoting this technical dossier reference.
            </p>
          </div>
        </div>

        {/* Modal Bottom Actions Bar */}
        <div className="p-4 sm:p-5 border-t border-slate-200 dark:border-night-border bg-slate-50 dark:bg-night-950 flex flex-col sm:flex-row items-center justify-between gap-3">
          <a
            href="https://cybercrime.gov.in"
            target="_blank"
            rel="noreferrer"
            className="text-xs text-indigo-600 dark:text-indigo-400 hover:underline flex items-center space-x-1.5 font-medium"
          >
            <span>Proceed to cybercrime.gov.in to file official complaint</span>
            <ExternalLink className="w-3.5 h-3.5" />
          </a>

          <div className="flex items-center space-x-2 w-full sm:w-auto justify-end">
            <button
              onClick={handlePrint}
              className="px-4 py-2 btn-primary text-xs shadow cursor-pointer"
            >
              Print / Save PDF
            </button>
            <button
              onClick={onClose}
              className="px-4 py-2 btn-secondary text-xs cursor-pointer"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
