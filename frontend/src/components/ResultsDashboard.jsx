import React, { useState } from 'react';
import {
  ShieldAlert,
  Copy,
  Check,
  FileText,
  ExternalLink,
  AlertTriangle,
  ShieldCheck,
  Clock,
  Layers,
  Sparkles,
  ArrowLeft,
  Search,
  Eye,
  Activity,
  CheckCircle2,
  RefreshCw,
  PhoneCall,
  BookmarkPlus
} from 'lucide-react';
import AdaptiveGuidance from './AdaptiveGuidance';
import AttackPath from './AttackPath';
import FraudDna from './FraudDna';
import EvidenceSection from './EvidenceSection';
import ThreatIntelCards from './ThreatIntelCards';
import ExplanationCard from './ExplanationCard';
import UrlInfrastructure from './UrlInfrastructure';
import ReportModal from './ReportModal';
import { TRANSLATIONS } from '../i18n/translations';

// Helper to construct a single plain-language verdict sentence
function getPlainLanguageVerdict(result) {
  if (result.explanation?.summary) {
    const summary = result.explanation.summary.trim();
    const firstPeriod = summary.indexOf('. ');
    if (firstPeriod > 20 && firstPeriod < 160) {
      return summary.substring(0, firstPeriod + 1);
    }
    return summary;
  }

  const riskLevel = (result.risk?.level || '').toUpperCase();
  const category = (result.fraud_category || '').toLowerCase();

  if (category.includes('electricity')) {
    return 'Critical Utility Scam: Coercive threat claiming power cutoff tonight to force an immediate payment to an unverified private number.';
  }
  if (category.includes('kyc') || category.includes('bank') || category.includes('sbi')) {
    return 'Critical Banking Phishing: Fraudulent message claiming account suspension to lure you into disclosing NetBanking credentials and OTP on a fake portal.';
  }
  if (category.includes('courier') || category.includes('postal')) {
    return 'Suspicious Delivery Scam: Deceptive notice requesting re-delivery fees via an unofficial website to harvest credit/debit card details.';
  }
  if (category.includes('upi') || category.includes('refund')) {
    return 'High-Risk Payment Scam: Fraudulent collect request designed to debit funds when you enter your UPI PIN instead of receiving money.';
  }
  if (category.includes('arrest') || category.includes('cbi') || category.includes('police')) {
    return 'Extortion / Digital Arrest Scam: Fake law enforcement summons exploiting fear to coerce victims into video calls and fraudulent fund transfers.';
  }
  if (riskLevel === 'CRITICAL' || riskLevel === 'HIGH') {
    return 'High-Risk Cyber Threat: Message exhibits coercive urgency, deceptive credential harvesting, or unverified external payment links.';
  }
  return 'Authentic / Low Risk Communication: Official notification with verified parameters. No credential theft or malicious indicators detected.';
}

export default function ResultsDashboard({
  result,
  currentUserState,
  onStateChange,
  isUpdatingState,
  onCheckAnother,
  lang,
  currentUser = null,
  onOpenAuthModal = () => {},
}) {
  // Mode: 'quick' (Level 1 + 2 concise) or 'full' (Level 3 Deep Forensic Evidence)
  const [viewMode, setViewMode] = useState('quick');
  const [copiedRef, setCopiedRef] = useState(false);
  const [reportModalOpen, setReportModalOpen] = useState(false);

  const t = TRANSLATIONS[lang] || TRANSLATIONS.en;

  if (!result) return null;

  const incidentId = result.incident_id || 'INC-2026-PENDING';
  const riskScore = Math.round((result.risk?.score || 0) * 100);
  const riskLevel = (result.risk?.level || 'UNKNOWN').toUpperCase();
  const isHighRisk = riskLevel === 'CRITICAL' || riskLevel === 'HIGH' || riskScore >= 70;
  const isSafe = riskLevel === 'LOW' || riskLevel === 'UNKNOWN' || riskScore < 40;

  const categoryLabel = result.fraud_category
    ? result.fraud_category.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
    : 'General Threat Evaluation';

  const verdictSentence = getPlainLanguageVerdict(result);

  const handleCopyRef = () => {
    navigator.clipboard.writeText(incidentId);
    setCopiedRef(true);
    setTimeout(() => setCopiedRef(false), 2000);
  };

  // Find most important detected finding
  const primaryEvidence = (result.evidence || [])[0]?.description ||
    (isHighRisk ? 'Coercive urgency & deceptive credentials harvesting indicators detected.' : 'No malicious markers found.');

  return (
    <div className="w-full max-w-5xl mx-auto space-y-6" id="results-dashboard" aria-live="polite">
      {/* ─── Top Control Bar: Back Navigation, Case ID, & View Switcher ─── */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-200/80 dark:border-border-dark">
        <button
          type="button"
          onClick={onCheckAnother}
          className="inline-flex items-center space-x-1.5 text-xs font-bold text-slate-700 hover:text-accent dark:text-slate-300 dark:hover:text-emerald-300 transition-colors cursor-pointer self-start focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500 rounded"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Check Another Message / Link</span>
        </button>

        <div className="flex items-center space-x-3 self-end sm:self-auto flex-wrap">
          {/* Reference ID Pill */}
          <div className="flex items-center space-x-2 px-3 py-1.5 rounded-xl bg-slate-100 dark:bg-surface-dark-elevated border border-slate-200 dark:border-border-dark text-xs shadow-2xs">
            <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">Case ID:</span>
            <span className="font-mono font-bold text-slate-900 dark:text-slate-100">{incidentId}</span>
            <button
              onClick={handleCopyRef}
              className="ml-1 text-slate-500 hover:text-slate-800 dark:hover:text-slate-200 transition-colors cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500 rounded"
              title="Copy Incident ID"
            >
              {copiedRef ? <Check className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          </div>

          {/* Quick View vs Full Evidence Segmented Switch */}
          <div className="flex items-center bg-slate-100 dark:bg-surface-dark-elevated p-1 rounded-xl border border-slate-200 dark:border-border-dark shadow-2xs" role="group" aria-label="Inspection Depth">
            <button
              type="button"
              onClick={() => setViewMode('quick')}
              className={`px-3.5 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500 ${
                viewMode === 'quick'
                  ? 'bg-slate-900 text-white dark:bg-emerald-600 dark:text-white shadow-sm'
                  : 'text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white'
                }`}
            >
              Quick View
            </button>
            <button
              type="button"
              onClick={() => setViewMode('full')}
              className={`px-3.5 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer flex items-center space-x-1 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500 ${
                viewMode === 'full'
                  ? 'bg-slate-900 text-white dark:bg-emerald-600 dark:text-white shadow-sm'
                  : 'text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white'
                }`}
            >
              <span>Full Dossier</span>
              <span className={`ml-1 px-1.5 py-0.2 rounded-full text-[10px] font-mono ${
                viewMode === 'full'
                  ? 'bg-white/20 text-white'
                  : 'bg-slate-200 dark:bg-surface-dark-hover text-slate-600 dark:text-slate-400'
              }`}>
                {(result.evidence || []).length}
              </span>
            </button>
          </div>
        </div>
      </div>

      {/* ─── SECTION 1: WHAT IS HAPPENING? ─── */}
      <section className={`clean-card clean-card-hover p-6 sm:p-7 relative overflow-hidden ${
        isHighRisk
          ? 'bg-rose-50/40 border-rose-200 dark:bg-rose-950/20 dark:border-rose-900/60'
          : isSafe
            ? 'bg-emerald-50/40 border-emerald-200 dark:bg-emerald-950/20 dark:border-emerald-900/60'
            : 'bg-amber-50/40 border-amber-200 dark:bg-amber-950/20 dark:border-amber-900/60'
      }`}>
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 relative z-10">
          <div className="space-y-3 flex-1">
            <div className="flex items-center space-x-2.5 flex-wrap gap-y-2">
              {/* Risk Level Badge */}
              <span className={`inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-extrabold tracking-wider uppercase ${
                isHighRisk
                  ? 'bg-rose-600 text-white'
                  : isSafe
                    ? 'bg-emerald-600 text-white'
                    : 'bg-amber-600 text-white'
              }`}>
                <span className="w-1.5 h-1.5 rounded-full bg-white" />
                <span>{isHighRisk ? 'CONFIRMED PHISHING' : isSafe ? 'VERIFIED BENIGN' : 'SUSPICIOUS'} • {riskScore}/100 RISK</span>
              </span>

              <span className="text-xs font-mono text-slate-500 dark:text-slate-400">
                Category: <strong className="text-slate-800 dark:text-slate-200 font-sans font-bold">{categoryLabel}</strong>
              </span>
            </div>

            {/* Plain-Language Verdict */}
            <h3 className="text-lg sm:text-xl font-bold text-slate-900 dark:text-white leading-snug">
              {verdictSentence}
            </h3>

            {/* Most Important Detected Issue */}
            <div className="p-3.5 rounded-xl bg-slate-50/80 dark:bg-surface-dark-elevated/70 border border-slate-200/80 dark:border-border-dark flex items-start space-x-2.5 text-xs text-slate-700 dark:text-slate-300">
              <span className="font-extrabold text-slate-900 dark:text-white flex-shrink-0">Key Finding:</span>
              <span>{primaryEvidence}</span>
            </div>
          </div>

          {/* Quick Score Circular Ring & Report Action */}
          <div className="flex sm:flex-col items-center justify-between sm:justify-center gap-4 self-start md:self-center flex-shrink-0">
            {/* Circular Gauge */}
            <div className="relative w-22 h-22 flex items-center justify-center">
              <svg className="w-full h-full -rotate-90 transform" viewBox="0 0 88 88">
                <circle
                  cx="44"
                  cy="44"
                  r="36"
                  className="stroke-slate-200 dark:stroke-surface-dark-hover"
                  strokeWidth="7"
                  fill="transparent"
                />
                <circle
                  cx="44"
                  cy="44"
                  r="36"
                  className={`transition-all duration-1000 ease-out ${
                    isHighRisk
                      ? 'stroke-rose-600 dark:stroke-rose-500'
                      : isSafe
                        ? 'stroke-emerald-600 dark:stroke-emerald-500'
                        : 'stroke-amber-600 dark:stroke-amber-500'
                  }`}
                  strokeWidth="7"
                  strokeDasharray={2 * Math.PI * 36}
                  strokeDashoffset={(2 * Math.PI * 36) - ((riskScore / 100) * (2 * Math.PI * 36))}
                  strokeLinecap="round"
                  fill="transparent"
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                <span className="text-xl font-black text-slate-900 dark:text-white leading-none">
                  {riskScore}
                </span>
                <span className="text-[9px] font-bold text-slate-400 dark:text-slate-500 uppercase tracking-wider mt-0.5">
                  / 100
                </span>
              </div>
            </div>

            <div className="flex flex-col gap-2 w-full sm:w-auto">
              <button
                type="button"
                onClick={() => setReportModalOpen(true)}
                className="inline-flex items-center justify-center space-x-1.5 px-4 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-white dark:bg-emerald-600 dark:hover:bg-emerald-500 dark:text-white text-xs font-bold shadow-card-elevated transition-all active:scale-[0.98] cursor-pointer"
              >
                <FileText className="w-3.5 h-3.5" />
                <span>Generate Dossier</span>
              </button>

              {!currentUser ? (
                <button
                  type="button"
                  onClick={() => onOpenAuthModal('Sign in to permanently archive this investigation into your Citizen Dossier.')}
                  className="inline-flex items-center justify-center space-x-1.5 px-3 py-1.5 rounded-xl border border-slate-300 dark:border-border-dark bg-white dark:bg-surface-dark-elevated hover:bg-slate-50 dark:hover:bg-surface-dark-hover text-slate-700 dark:text-slate-300 text-[11px] font-semibold transition-all cursor-pointer"
                >
                  <BookmarkPlus className="w-3.5 h-3.5 text-emerald-500" />
                  <span>Save to Account</span>
                </button>
              ) : (
                <span className="inline-flex items-center justify-center space-x-1 text-[11px] font-mono text-emerald-600 dark:text-emerald-400 font-semibold py-1">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>Saved in My Checks</span>
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Evidentiary Artifact & Threat Analysis Card */}
        {result.message && (
          <div className="mt-5 pt-4 border-t border-slate-200/80 dark:border-border-dark space-y-3">
            <div className="flex items-center justify-between text-xs">
              <span className="font-bold text-slate-800 dark:text-slate-200 uppercase tracking-wider text-[11px]">
                Evidentiary Artifact & Threat Analysis
              </span>
              <span className="text-[10px] font-mono text-slate-400">Untrusted Communication</span>
            </div>

            <div className="p-3.5 rounded-xl bg-white dark:bg-surface-dark-elevated border border-slate-200 dark:border-border-dark font-mono text-xs text-slate-800 dark:text-slate-200 leading-relaxed whitespace-pre-wrap break-words">
              {result.message}
            </div>

            {/* IOC extraction table */}
            {result.urls && result.urls.length > 0 && (
              <div className="overflow-x-auto border border-slate-200 dark:border-border-dark rounded-xl">
                <table className="w-full text-left text-xs font-mono">
                  <thead>
                    <tr className="bg-slate-100 dark:bg-surface-dark-elevated border-b border-slate-200 dark:border-border-dark text-slate-600 dark:text-slate-400 text-[10px]">
                      <th className="p-2.5">Indicator Type</th>
                      <th className="p-2.5">Observed Artifact</th>
                      <th className="p-2.5">Classification</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-border-dark bg-white dark:bg-surface-dark">
                    {result.urls.map((u, idx) => (
                      <tr key={idx}>
                        <td className="p-2.5 text-slate-500">Extracted URL</td>
                        <td className="p-2.5 text-slate-800 dark:text-slate-200 break-all">{u.url}</td>
                        <td className="p-2.5">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            u.is_suspicious ? 'bg-rose-50 text-rose-700 dark:bg-rose-950/60 dark:text-rose-300' : 'bg-emerald-50 text-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-300'
                          }`}>
                            {u.is_suspicious ? 'SUSPICIOUS' : 'CLEAN'}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </section>

      {/* ─── SECTION 2: WHAT SHOULD I DO? ─── */}
      <section aria-label="What Should I Do">
        <AdaptiveGuidance
          response={result.response}
          currentState={currentUserState}
          onStateChange={onStateChange}
          isUpdatingState={isUpdatingState}
          incidentId={incidentId}
        />
      </section>

      {/* ─── VIEW MODE: FULL EVIDENCE (DEEP SCAN LEVEL 3) ─── */}
      {viewMode === 'full' ? (
        <div className="space-y-6 pt-2 border-t border-slate-200 dark:border-border-dark">
          {/* SECTION 3: WHY DID YOU SAY THAT? (Epistemic Reasoning) */}
          <ExplanationCard explanation={result.explanation} />

          {/* SECTION 4: SHOW ME THE EVIDENCE (Collapsible Accordions) */}
          <EvidenceSection
            evidenceItems={result.evidence || []}
            incidentId={incidentId}
            extractedDomain={result.urls?.[0]?.domain || null}
          />

          {/* SECTION 5: SHOW ME THE ATTACK PATH */}
          <AttackPath
            attackPath={result.attack_path}
            fraudCategory={result.fraud_category}
            userState={currentUserState}
          />

          {/* SECTION 6: THREAT INTELLIGENCE & DOMAIN INFRASTRUCTURE */}
          <ThreatIntelCards
            threatIntel={result.threat_intel}
            brandAnalysis={result.brand_impersonation}
          />

          {result.urls && result.urls.length > 0 && (
            <UrlInfrastructure urls={result.urls} threatIntel={result.threat_intel} />
          )}

          {/* SECTION 7: FRAUD DNA SYNDICATE CORRELATION */}
          <FraudDna 
            fraudDna={result.fraud_dna} 
            targetBrand={result.brand_impersonation?.target_brand}
            extractedDomain={result.urls?.[0]?.domain}
          />
        </div>
      ) : (
        /* In Quick View: Provide an obvious, friendly banner to inspect deeper evidence */
        <div className="clean-card clean-card-hover p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div>
            <h4 className="text-xs font-bold text-slate-900 dark:text-white">
              Want to inspect forensic evidence, threat feeds, or the attack path?
            </h4>
            <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
              {(result.evidence || []).length} forensic signals extracted across Safe Browsing, PhishTank, PhishStats, and epistemic reasoning.
            </p>
          </div>

          <button
            type="button"
            onClick={() => setViewMode('full')}
            className="inline-flex items-center space-x-1.5 px-4 py-2 rounded-xl bg-white dark:bg-surface-dark-hover hover:bg-slate-100 dark:hover:bg-surface-dark-elevated border border-slate-200 dark:border-border-dark text-slate-800 dark:text-slate-200 text-xs font-bold transition-all cursor-pointer shadow-xs active:scale-95 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500"
          >
            <Eye className="w-3.5 h-3.5 text-accent dark:text-emerald-400" />
            <span>Switch to Full Evidence View</span>
          </button>
        </div>
      )}

      {/* ─── SECTION 8: REPORT THIS INCIDENT (Formal Reporting Flow) ─── */}
      <section className="clean-card clean-card-hover p-5 sm:p-6 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h4 className="text-sm font-bold text-slate-900 dark:text-white flex items-center space-x-2">
              <FileText className="w-4 h-4 text-accent dark:text-emerald-400" />
              <span>Official Law Enforcement & 1930 Incident Dossier</span>
            </h4>
            <p className="text-xs text-slate-600 dark:text-slate-400 mt-0.5">
              Generate a verified, printable legal complaint preview containing cryptographic SHA-256 hash, extracted IOCs, and forensic evidence for submission to <strong className="text-slate-900 dark:text-white">cybercrime.gov.in</strong> or dialling <strong className="text-slate-900 dark:text-white">1930</strong>.
            </p>
          </div>

          <button
            type="button"
            onClick={() => setReportModalOpen(true)}
            className="inline-flex items-center space-x-2 px-5 py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 text-white dark:bg-emerald-600 dark:hover:bg-emerald-500 text-xs font-bold shadow-card-elevated transition-all active:scale-[0.98] cursor-pointer flex-shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500"
          >
            <FileText className="w-4 h-4" />
            <span>Generate Incident Report</span>
          </button>
        </div>
      </section>

      {/* ─── Report Modal ─── */}
      <ReportModal
        isOpen={reportModalOpen}
        onClose={() => setReportModalOpen(false)}
        result={result}
        incidentId={incidentId}
      />
    </div>
  );
}
