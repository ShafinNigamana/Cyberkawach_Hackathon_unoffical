import React, { useState } from 'react';
import { Shield, ChevronDown, ChevronUp, ExternalLink, Lock, CheckCircle2 } from 'lucide-react';

export default function Footer({ onOpenMethodology }) {
  const [mobilePortalOpen, setMobilePortalOpen] = useState(false);
  const [mobileGuaranteesOpen, setMobileGuaranteesOpen] = useState(false);

  return (
    <footer className="w-full bg-slate-100 border-t border-slate-200 text-slate-600 dark:bg-slate-950 dark:border-slate-800 dark:text-slate-400 text-xs mt-12 py-8 px-4 sm:px-6 select-none transition-colors" role="contentinfo">
      <div className="max-w-7xl mx-auto space-y-8">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 pb-8 border-b border-slate-200 dark:border-slate-800/80">
          {/* Col 1: Identity & Partnership */}
          <div className="space-y-3">
            <div className="flex items-center space-x-2.5">
              <div className="w-8 h-8 rounded-lg bg-blue-900 dark:bg-blue-950 border border-amber-500/80 flex items-center justify-center flex-shrink-0 shadow-xs">
                <Shield className="w-4 h-4 text-amber-400" />
              </div>
              <div>
                <h4 className="text-sm font-bold text-slate-900 dark:text-white">Cyber Fraud Guardian</h4>
                <p className="text-[11px] text-slate-500 dark:text-slate-400">
                  Indian Cyber Crime Coordination Centre (I4C) Partner Initiative • Track S2
                </p>
              </div>
            </div>

            <p className="text-[11px] text-slate-600 dark:text-slate-400 leading-relaxed">
              An evidence-driven, epistemically grounded cyber threat classification and triage framework built for the Cyber Kavach Challenge 2026, BSides Ahmedabad.
            </p>

            <button
              onClick={onOpenMethodology}
              className="inline-flex items-center space-x-1 text-blue-700 dark:text-amber-400 hover:text-blue-900 dark:hover:text-amber-300 text-xs font-bold underline underline-offset-2 cursor-pointer"
            >
              <span>View Technical Methodology & Audits</span>
              <ExternalLink className="w-3 h-3" />
            </button>
          </div>

          {/* Col 2: Official National Portals (Responsive accordion on mobile) */}
          <div>
            <div 
              className="flex items-center justify-between cursor-pointer md:cursor-default mb-2"
              onClick={() => setMobilePortalOpen(!mobilePortalOpen)}
            >
              <h5 className="text-xs font-bold text-slate-900 dark:text-white uppercase tracking-wider">
                Official National Portals
              </h5>
              <span className="md:hidden">
                {mobilePortalOpen ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
              </span>
            </div>

            <div className={`space-y-2 pt-1 ${mobilePortalOpen ? 'block' : 'hidden md:block'}`}>
              <ul className="space-y-1.5 text-[11px]">
                <li>
                  <a href="https://cybercrime.gov.in" target="_blank" rel="noreferrer" className="text-slate-600 dark:text-slate-400 hover:text-blue-800 dark:hover:text-amber-300 flex items-center space-x-1">
                    <span>National Cyber Crime Reporting Portal (1930)</span>
                    <ExternalLink className="w-2.5 h-2.5 text-slate-400 dark:text-slate-500" />
                  </a>
                </li>
                <li>
                  <a href="https://sachet.rbi.org.in" target="_blank" rel="noreferrer" className="text-slate-600 dark:text-slate-400 hover:text-blue-800 dark:hover:text-amber-300 flex items-center space-x-1">
                    <span>RBI Sachet (Unauthorised Schemes)</span>
                    <ExternalLink className="w-2.5 h-2.5 text-slate-400 dark:text-slate-500" />
                  </a>
                </li>
                <li>
                  <a href="https://sancharsaathi.gov.in/sfc/" target="_blank" rel="noreferrer" className="text-slate-600 dark:text-slate-400 hover:text-blue-800 dark:hover:text-amber-300 flex items-center space-x-1">
                    <span>Chakshu Telecom Fraud Reporting</span>
                    <ExternalLink className="w-2.5 h-2.5 text-slate-400 dark:text-slate-500" />
                  </a>
                </li>
                <li>
                  <a href="https://www.cert-in.org.in" target="_blank" rel="noreferrer" className="text-slate-600 dark:text-slate-400 hover:text-blue-800 dark:hover:text-amber-300 flex items-center space-x-1">
                    <span>CERT-In National Security Advisories</span>
                    <ExternalLink className="w-2.5 h-2.5 text-slate-400 dark:text-slate-500" />
                  </a>
                </li>
              </ul>
            </div>
          </div>

          {/* Col 3: Privacy & Security Guarantees (Responsive accordion on mobile) */}
          <div>
            <div 
              className="flex items-center justify-between cursor-pointer md:cursor-default mb-2"
              onClick={() => setMobileGuaranteesOpen(!mobileGuaranteesOpen)}
            >
              <h5 className="text-xs font-bold text-slate-900 dark:text-white uppercase tracking-wider">
                Citizen Privacy Guarantees
              </h5>
              <span className="md:hidden">
                {mobileGuaranteesOpen ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
              </span>
            </div>

            <div className={`space-y-2 pt-1 ${mobileGuaranteesOpen ? 'block' : 'hidden md:block'}`}>
              <div className="p-3 bg-white dark:bg-slate-900 rounded-btn border border-slate-200 dark:border-slate-800 space-y-2 shadow-xs">
                <div className="flex items-start space-x-2">
                  <Lock className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400 mt-0.5 flex-shrink-0" />
                  <span className="text-[11px] text-slate-700 dark:text-slate-300">
                    <strong className="text-slate-900 dark:text-white">Zero Data Retention:</strong> Messages are held in ephemeral memory and discarded after analysis.
                  </span>
                </div>
                <div className="flex items-start space-x-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400 mt-0.5 flex-shrink-0" />
                  <span className="text-[11px] text-slate-700 dark:text-slate-300">
                    <strong className="text-slate-900 dark:text-white">In-Memory Token Redaction:</strong> Aadhaar & OTP numbers are expunged prior to evaluation.
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Bottom Bar */}
        <div className="flex flex-col sm:flex-row items-center justify-between text-[11px] text-slate-500 gap-2">
          <p>© 2026 Cyber Fraud Guardian • Open-Source Public Interest Cyber Defense Framework.</p>
          <div className="flex items-center space-x-3">
            <span className="px-2 py-0.5 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-400 font-mono text-[10px]">
              Ponytail Standard
            </span>
            <span className="px-2 py-0.5 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-400 font-mono text-[10px]">
              WCAG AA Verified
            </span>
            <span className="px-2 py-0.5 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-400 font-mono text-[10px]">
              Zero PII Leakage
            </span>
          </div>
        </div>
      </div>
    </footer>
  );
}
