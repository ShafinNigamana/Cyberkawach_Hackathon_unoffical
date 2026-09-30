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
      className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-slate-950/80 backdrop-blur-sm overflow-y-auto"
      role="dialog"
      aria-modal="true"
      aria-label="Forensic Incident Dossier Preview"
    >
      <div className="bg-slate-900 border border-slate-700 rounded-card max-w-4xl w-full max-h-[90vh] flex flex-col shadow-2xl text-slate-200">
        {/* Modal Top Bar */}
        <div className="flex items-center justify-between p-4 border-b border-slate-800 bg-slate-950/60 rounded-t-card">
          <div className="flex items-center space-x-2.5">
            <ShieldAlert className="w-5 h-5 text-amber-400" />
            <div>
              <h3 className="text-sm sm:text-base font-bold text-white">
                Official Cyber Crime Forensic Incident Dossier
              </h3>
              <p className="text-[11px] text-slate-400">
                Citizen Technical Pack for National Cyber Crime Helpline (1930) & State Police
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={handlePrint}
              className="inline-flex items-center space-x-1.5 px-3 py-1.5 bg-white hover:bg-slate-100 text-slate-950 rounded-lg text-xs font-semibold shadow transition-colors cursor-pointer"
              title="Print official dossier or save to PDF"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>Print / Save PDF</span>
            </button>

            <button
              onClick={handleDownloadJson}
              className="inline-flex items-center space-x-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-btn text-xs font-medium transition-colors cursor-pointer"
              title="Download structured JSON forensic export"
            >
              <Download className="w-3.5 h-3.5 text-slate-400" />
              <span>JSON</span>
            </button>

            <button
              onClick={onClose}
              className="p-1.5 rounded-btn hover:bg-slate-800 text-slate-400 hover:text-white transition-colors cursor-pointer"
              aria-label="Close Preview"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Printable Document Preview Area */}
        <div className="p-5 sm:p-8 overflow-y-auto space-y-6 font-sans text-xs bg-slate-950/40">
          {/* Official Emblem Banner */}
          <div className="text-center pb-4 border-b border-slate-800">
            <div className="inline-block p-2 bg-slate-900 rounded-full border border-slate-700 mb-2">
              <svg viewBox="0 0 24 24" width="28" height="28" fill="currentColor" className="text-amber-400 mx-auto" aria-hidden="true">
                <circle cx="12" cy="12" r="10" fill="none" stroke="currentColor" strokeWidth="1.5" />
                <circle cx="12" cy="12" r="2" fill="currentColor" />
                <path d="M12 2v20M2 12h20M4.93 4.93l14.14 14.14M4.93 19.07L19.07 4.93M8.46 2.54l7.08 18.92M2.54 8.46l18.92 7.08M15.54 2.54L8.46 21.46M2.54 15.54l18.92-7.08" stroke="currentColor" strokeWidth="0.8" />
              </svg>
            </div>
            <h2 className="text-base font-bold text-white uppercase tracking-wider">
              CYBER FRAUD FORENSIC INCIDENT DOSSIER
            </h2>
            <p className="text-[11px] text-slate-400">
              Generated by Cyber Fraud Guardian • I4C Partner Initiative • National Citizen Triage Dossier
            </p>
          </div>

          {/* Dossier Identifiers Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 p-4 bg-slate-900/80 rounded-btn border border-slate-800 font-mono text-xs">
            <div>
              <span className="text-slate-400 block text-[10px]">INCIDENT REFERENCE ID:</span>
              <div className="flex items-center space-x-2 mt-0.5">
                <strong className="text-amber-400 text-sm">{effectiveId}</strong>
                <button
                  onClick={() => handleCopy(effectiveId)}
                  className="p-1 hover:bg-slate-800 rounded text-slate-400 hover:text-white cursor-pointer"
                  title="Copy Reference ID"
                >
                  {isCopied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
            </div>

            <div>
              <span className="text-slate-400 block text-[10px]">THREAT CLASSIFICATION:</span>
              <div className="mt-0.5">
                <span className={`inline-block px-2 py-0.5 rounded-badge text-xs font-bold border ${
                  riskLevel === 'CRITICAL' || riskLevel === 'HIGH' 
                    ? 'bg-red-950 text-red-300 border-red-700' 
                    : 'bg-emerald-950 text-emerald-300 border-emerald-700'
                }`}>
                  {riskLevel} ({riskScorePct}/100)
                </span>
                <span className="text-slate-400 text-xs ml-2">
                  Category: {currentIncident.fraud_category || 'General Scam'}
                </span>
              </div>
            </div>
          </div>

          {/* Section 1: Untrusted Evidentiary Message */}
          <div>
            <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wide mb-1.5">
              1. Untrusted Evidentiary Communication
            </h4>
            <div className="p-3 bg-slate-950 border border-slate-800 rounded-btn font-mono text-[11px] text-slate-300 whitespace-pre-wrap break-words leading-relaxed">
              {currentIncident.message_preview || currentIncident.message || 'No text content available'}
            </div>
          </div>

          {/* Section 2: Indicators of Compromise (IOCs) */}
          {currentIncident.urls && currentIncident.urls.length > 0 && (
            <div>
              <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wide mb-1.5">
                2. Extracted Indicators of Compromise (IOCs)
              </h4>
              <div className="overflow-x-auto border border-slate-800 rounded-btn">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="bg-slate-900 border-b border-slate-800 text-slate-400 font-mono text-[11px]">
                      <th className="p-2.5">Type</th>
                      <th className="p-2.5">Observed Value / URL</th>
                      <th className="p-2.5">Classification</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/80 font-mono">
                    {currentIncident.urls.map((u, i) => (
                      <tr key={i} className="hover:bg-slate-900/40">
                        <td className="p-2.5 text-slate-400">Web URL</td>
                        <td className="p-2.5 text-slate-200 break-all">{u.url}</td>
                        <td className="p-2.5 text-amber-400">{u.is_suspicious ? 'Suspicious' : 'Clean'}</td>
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
              <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wide mb-1.5">
                3. Forensic Evidence Dossier
              </h4>
              <div className="overflow-x-auto border border-slate-800 rounded-btn">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="bg-slate-900 border-b border-slate-800 text-slate-400 font-mono text-[11px]">
                      <th className="p-2.5">Source Module</th>
                      <th className="p-2.5">Finding & Forensic Description</th>
                      <th className="p-2.5">Confidence</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/80">
                    {currentIncident.evidence.map((item, i) => (
                      <tr key={i} className="hover:bg-slate-900/40">
                        <td className="p-2.5 font-mono text-slate-400 whitespace-nowrap">{item.source}</td>
                        <td className="p-2.5 text-slate-200">{item.description}</td>
                        <td className="p-2.5 font-mono text-amber-400 whitespace-nowrap">
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
          <div className="p-4 bg-slate-900/80 rounded-btn border border-slate-800 text-slate-300 space-y-1.5">
            <h4 className="text-xs font-bold text-white uppercase tracking-wide flex items-center space-x-1.5">
              <span>National Cyber Crime Reporting Advisory</span>
            </h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              If financial loss occurred within the last 24 hours (Golden Hour), immediately call <strong>1930</strong> or register an online formal complaint at <a href="https://cybercrime.gov.in" target="_blank" rel="noreferrer" className="text-blue-400 underline">https://cybercrime.gov.in</a> quoting this technical dossier reference.
            </p>
          </div>
        </div>

        {/* Modal Bottom Actions Bar */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/80 flex flex-col sm:flex-row items-center justify-between gap-3 rounded-b-card">
          <a
            href="https://cybercrime.gov.in"
            target="_blank"
            rel="noreferrer"
            className="text-xs text-blue-400 hover:text-blue-300 flex items-center space-x-1"
          >
            <span>Proceed to cybercrime.gov.in to file official complaint</span>
            <ExternalLink className="w-3.5 h-3.5" />
          </a>

          <div className="flex items-center space-x-2">
            <button
              onClick={handlePrint}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white font-semibold rounded-btn text-xs shadow transition-colors"
            >
              Print / Save PDF
            </button>
            <button
              onClick={onClose}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-btn text-xs transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
